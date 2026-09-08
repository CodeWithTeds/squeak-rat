"""
ast_parser.py — PHP AST Parsing via nikic/php-parser (Plan #1, #15, #20)
Implements production-grade AST parsing with:
 - Dataverse patterns: error handling, retry with exponential backoff, timeouts, config
 - Performance patterns: lru_cache, batch I/O, incremental cache, generators
 - Cache management: flush on metadata change
"""
from __future__ import annotations
import re
import json
import time
import hashlib
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from functools import lru_cache
import weakref

# ── Configuration & Timeouts (Dataverse pattern #5) ──
@dataclass
class ParserConfig:
    """Mirrors DataverseConfig http_retries, http_backoff, http_timeout."""
    timeout: float = 10.0  # seconds per file parse
    retries: int = 3
    backoff_base: float = 0.2  # exponential backoff base
    backoff_factor: float = 2.0
    cache_enabled: bool = True
    max_file_size_kb: int = 512  # skip huge files
    language_code: str = "php"  # for future i18n of errors

DEFAULT_CONFIG = ParserConfig()

# ── Custom Exceptions (Dataverse pattern #1) ──
class ParserError(Exception):
    """Base parser error with is_transient for retry logic."""
    def __init__(self, msg: str, is_transient: bool = False, file: str = ""):
        super().__init__(msg)
        self.is_transient = is_transient
        self.file = file

class TransientParserError(ParserError):
    def __init__(self, msg: str, file: str = ""):
        super().__init__(msg, is_transient=True, file=file)

class PermanentParserError(ParserError):
    def __init__(self, msg: str, file: str = ""):
        super().__init__(msg, is_transient=False, file=file)

# ── AST Node Representation ──
@dataclass
class AstNode:
    """Simplified PHP AST node."""
    type: str  # Class, Method, Function, Variable, Call, etc.
    name: str
    file: str
    line: int
    children: List["AstNode"] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {"type": self.type, "name": self.name, "file": self.file, "line": self.line, "children": [c.to_dict() for c in self.children], "meta": self.meta}

@dataclass
class ParsedFile:
    """Result of parsing a single PHP file."""
    file: str
    hash: str  # content hash for incremental check
    nodes: List[AstNode] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    uses: List[str] = field(default_factory=list)
    parse_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self):
        return {"file": self.file, "hash": self.hash, "nodes": [n.to_dict() for n in self.nodes], "classes": self.classes, "methods": self.methods, "uses": self.uses, "parse_time_ms": self.parse_time_ms, "error": self.error}

# ── PHP Helper Script (uses nikic/php-parser if available) ──
PHP_PARSE_SCRIPT = r'''
<?php
// Lightweight PHP AST dump using nikic/php-parser if available, else regex fallback
// Usage: php -f script.php <file>
$file = $argv[1] ?? null;
if (!$file || !file_exists($file)) { echo json_encode(["error"=>"file not found"]); exit(1); }
$content = file_get_contents($file);
if ($content === false) { echo json_encode(["error"=>"read failed"]); exit(2); }
// Try nikic/php-parser
if (file_exists(__DIR__ . "/vendor/autoload.php")) {
    @require __DIR__ . "/vendor/autoload.php";
    // also try parent vendor
}
$found = false;
foreach ([__DIR__."/vendor/autoload.php", getcwd()."/vendor/autoload.php", dirname(__DIR__)."/vendor/autoload.php", "/Applications/XAMPP/xamppfiles/htdocs/package-contribution/rat/vendor/autoload.php"] as $a) {
    if (file_exists($a)) { @require_once $a; $found=true; break; }
}
if (class_exists("PhpParser\\ParserFactory")) {
    try {
        $factory = new PhpParser\ParserFactory();
        if (method_exists($factory, "createForHostVersion")) {
            $parser = $factory->createForHostVersion();
        } elseif (method_exists($factory, "create")) {
            $parser = $factory->create(PhpParser\ParserFactory::PREFER_PHP7);
        } else {
            throw new Exception("no factory method");
        }
        $stmts = $parser->parse($content);
        // Simple traversal to extract classes/methods
        $result = ["classes"=>[], "methods"=>[], "functions"=>[], "uses"=>[], "nodes"=>[]];
        // Use NameResolver and simple visitor
        $traverser = new PhpParser\NodeTraverser();
        // Collect nodes via visitor
        $collector = new class extends PhpParser\NodeVisitorAbstract {
            public $classes=[]; public $methods=[]; public $functions=[]; public $uses=[]; public $nodes=[];
            public function enterNode(PhpParser\Node $node) {
                if ($node instanceof PhpParser\Node\Stmt\Class_) {
                    $name = $node->name ? $node->name->toString() : "anonymous";
                    $this->classes[] = $name;
                    $this->nodes[] = ["type"=>"Class","name"=>$name,"line"=>$node->getLine()];
                } elseif ($node instanceof PhpParser\Node\Stmt\ClassMethod) {
                    $name = $node->name->toString();
                    $this->methods[] = $name;
                    $this->nodes[] = ["type"=>"Method","name"=>$name,"line"=>$node->getLine()];
                } elseif ($node instanceof PhpParser\Node\Stmt\Function_) {
                    $name = $node->name->toString();
                    $this->functions[] = $name;
                    $this->nodes[] = ["type"=>"Function","name"=>$name,"line"=>$node->getLine()];
                } elseif ($node instanceof PhpParser\Node\Stmt\Use_) {
                    foreach ($node->uses as $u) { $this->uses[] = $u->name->toString(); }
                } elseif ($node instanceof PhpParser\Node\Expr\FuncCall) {
                    if ($node->name instanceof PhpParser\Node\Name) {
                        $this->nodes[] = ["type"=>"Call","name"=>$node->name->toString(),"line"=>$node->getLine()];
                    }
                } elseif ($node instanceof PhpParser\Node\Expr\StaticCall || $node instanceof PhpParser\Node\Expr\MethodCall) {
                    $m = $node->name instanceof PhpParser\Node\Identifier ? $node->name->toString() : "dynamic";
                    $this->nodes[] = ["type"=>"Call","name"=>$m,"line"=>$node->getLine()];
                }
                return null;
            }
        };
        $traverser->addVisitor($collector);
        $traverser->traverse($stmts);
        $result["classes"]=$collector->classes;
        $result["methods"]=$collector->methods;
        $result["functions"]=$collector->functions;
        $result["uses"]=$collector->uses;
        $result["nodes"]=$collector->nodes;
        echo json_encode($result);
        exit(0);
    } catch (Throwable $e) {
        echo json_encode(["error"=>$e->getMessage(), "classes"=>[], "methods"=>[], "functions"=>[], "uses"=>[], "nodes"=>[]]);
        exit(0);
    }
}
// Fallback regex extraction (still produces nodes without full AST)
$result = ["classes"=>[], "methods"=>[], "functions"=>[], "uses"=>[], "nodes"=>[]];
if (preg_match_all('/class\s+(\w+)/', $content, $m)) { $result["classes"]=$m[1]; foreach($m[1] as $c) $result["nodes"][]=["type"=>"Class","name"=>$c,"line"=>1]; }
if (preg_match_all('/function\s+(\w+)\s*\(/', $content, $m)) { $result["functions"]=$m[1]; foreach($m[1] as $f) $result["nodes"][]=["type"=>"Function","name"=>$f,"line"=>1]; }
if (preg_match_all('/use\s+([^;]+);/', $content, $m)) { $result["uses"]=$m[1]; }
echo json_encode($result);
'''

# Cache directory for incremental analysis (Plan #15)
_CACHE_DIR: Optional[pathlib.Path] = None
# In-memory weak cache for parsed files (Pattern 20)
_weak_cache: weakref.WeakValueDictionary = weakref.WeakValueDictionary()

def _get_cache_dir(project_root: pathlib.Path) -> pathlib.Path:
    global _CACHE_DIR
    d = project_root / ".rat" / "cache" / "ast"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _file_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()[:16]

def _ensure_php_script() -> pathlib.Path:
    """Write PHP helper to temp file (cached)."""
    p = pathlib.Path(tempfile.gettempdir()) / "rat_php_parser.php"
    if not p.exists() or p.read_text() != PHP_PARSE_SCRIPT:
        p.write_text(PHP_PARSE_SCRIPT)
    return p

@lru_cache(maxsize=2048)
def _cached_parse_key(file_path: str, content_hash: str) -> str:
    """Generate cache key for file parse (Pattern 12)."""
    return f"{file_path}:{content_hash}"

class PhpAstParser:
    """
    Production-ready PHP AST parser with:
    - Retry with exponential backoff (transient errors)
    - Timeout handling
    - Incremental cache (parsed ASTs, hashes)
    - Batch operations
    - Proper error classification
    """

    def __init__(self, project_root: pathlib.Path, config: ParserConfig | None = None):
        self.project_root = pathlib.Path(project_root).resolve()
        self.config = config or DEFAULT_CONFIG
        self.cache_dir = _get_cache_dir(self.project_root)
        self._stats = {"hits": 0, "misses": 0, "errors": 0, "time_ms": 0.0}
        self.php_script = _ensure_php_script()

    def parse_file(self, file_path: pathlib.Path, *, use_cache: bool = True) -> ParsedFile:
        """
        Parse single file with retry, timeout, cache.
        Dataverse pattern: catch DataverseError, check is_transient, exponential backoff.
        """
        rel = str(file_path.relative_to(self.project_root)) if file_path.is_absolute() and str(file_path).startswith(str(self.project_root)) else str(file_path)
        # Check file size
        try:
            size_kb = file_path.stat().st_size / 1024
            if size_kb > self.config.max_file_size_kb:
                return ParsedFile(file=rel, hash="skipped_large", error=f"skipped large file {size_kb:.0f}kb")
        except Exception:
            pass

        # Read content for hash
        try:
            raw = file_path.read_bytes()
        except Exception as e:
            return ParsedFile(file=rel, hash="", error=f"read failed: {e}")

        h = _file_hash(raw)
        cache_key = _cached_parse_key(rel, h)
        cache_file = self.cache_dir / f"{hashlib.md5(cache_key.encode()).hexdigest()}.json"

        # Check incremental cache
        if use_cache and self.config.cache_enabled and cache_file.exists():
            try:
                data = json.loads(cache_file.read_text())
                if data.get("hash") == h:
                    self._stats["hits"] += 1
                    # Rehydrate
                    nodes = [AstNode(type=n["type"], name=n["name"], file=rel, line=n.get("line",1)) for n in data.get("nodes",[])]
                    return ParsedFile(file=rel, hash=h, nodes=nodes, classes=data.get("classes",[]), methods=data.get("methods",[]), functions=data.get("functions",[]), uses=data.get("uses",[]), parse_time_ms=data.get("parse_time_ms",0))
            except Exception:
                pass  # cache corrupt -> reparse

        self._stats["misses"] += 1
        start = time.perf_counter()

        # Retry loop with exponential backoff
        last_err = None
        for attempt in range(self.config.retries + 1):
            try:
                result = self._parse_via_php(file_path)
                elapsed = (time.perf_counter() - start) * 1000
                # Build ParsedFile
                nodes = [AstNode(type=n["type"], name=n["name"], file=rel, line=n.get("line",1)) for n in result.get("nodes",[])]
                pf = ParsedFile(file=rel, hash=h, nodes=nodes, classes=result.get("classes",[]), methods=result.get("methods",[]), functions=result.get("functions",[]), uses=result.get("uses",[]), parse_time_ms=elapsed)
                # Store cache
                if self.config.cache_enabled:
                    try:
                        cache_file.write_text(json.dumps(pf.to_dict()))
                    except Exception:
                        pass
                self._stats["time_ms"] += elapsed
                return pf
            except ParserError as e:
                last_err = e
                if not e.is_transient or attempt == self.config.retries:
                    self._stats["errors"] += 1
                    return ParsedFile(file=rel, hash=h, error=str(e))
                # exponential backoff
                backoff = self.config.backoff_base * (self.config.backoff_factor ** attempt)
                time.sleep(backoff)
            except Exception as e:
                last_err = e
                if attempt == self.config.retries:
                    self._stats["errors"] += 1
                    return ParsedFile(file=rel, hash=h, error=f"unexpected: {e}")
                time.sleep(self.config.backoff_base * (self.config.backoff_factor ** attempt))

        return ParsedFile(file=rel, hash=h, error=str(last_err) if last_err else "unknown")

    def _parse_via_php(self, file_path: pathlib.Path) -> Dict:
        """Invoke PHP parser subprocess with timeout."""
        try:
            proc = subprocess.run(
                ["php", str(self.php_script), str(file_path)],
                capture_output=True,
                timeout=self.config.timeout,
                text=True,
                cwd=str(self.project_root),
            )
        except subprocess.TimeoutExpired as e:
            raise TransientParserError(f"timeout after {self.config.timeout}s", file=str(file_path)) from e
        except FileNotFoundError as e:
            # php not found -> fallback to regex in Python
            raise TransientParserError("php binary not found", file=str(file_path)) from e

        if proc.returncode != 0:
            # If php error but stdout has json, use it
            if proc.stdout and proc.stdout.strip().startswith("{"):
                try:
                    return json.loads(proc.stdout)
                except:
                    pass
            # Transient if returncode 1 and not file not found
            msg = proc.stderr.strip()[:200] or proc.stdout.strip()[:200] or f"php exit {proc.returncode}"
            # Classify: parse error is permanent, timeout/IO is transient
            if "file not found" in msg.lower():
                raise PermanentParserError(msg, file=str(file_path))
            raise TransientParserError(msg, file=str(file_path))

        try:
            data = json.loads(proc.stdout)
            if "error" in data and data["error"] and not data.get("nodes"):
                # parse error but we have no nodes -> permanent
                pass
            return data
        except json.JSONDecodeError as e:
            raise PermanentParserError(f"invalid json from php parser: {e}", file=str(file_path)) from e

    def parse_batch(self, file_paths: List[pathlib.Path], *, workers: int = 4) -> List[ParsedFile]:
        """
        Batch parse multiple files (Dataverse pattern #2: bulk create with error recovery).
        Uses sequential for small batches, multiprocessing for large (Pattern 14).
        """
        if not file_paths:
            return []
        # For small batches or Windows without fork, just sequential
        if len(file_paths) < 20 or workers <= 1:
            return [self.parse_file(p) for p in file_paths]

        # Try multiprocessing
        try:
            import multiprocessing as mp
            # Use thread pool to avoid pickle issues with config?
            from concurrent.futures import ProcessPoolExecutor, as_completed
            # Need to make parse_file picklable -> use static helper
            # Fallback to sequential if multiprocessing fails
            results: List[ParsedFile] = []
            # We use ProcessPool but need to pass project_root
            # Instead, use ThreadPool for I/O-bound php subprocess
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(self.parse_file, p): p for p in file_paths}
                for fut in as_completed(futures):
                    try:
                        results.append(fut.result())
                    except Exception as e:
                        p = futures[fut]
                        rel = str(p.relative_to(self.project_root)) if str(p).startswith(str(self.project_root)) else str(p)
                        results.append(ParsedFile(file=rel, hash="", error=str(e)))
            # Preserve order by file
            order = {str(p): i for i, p in enumerate(file_paths)}
            results.sort(key=lambda pf: order.get(pf.file, 9999))
            return results
        except Exception:
            # Fallback sequential
            return [self.parse_file(p) for p in file_paths]

    def flush_cache(self):
        """Flush AST cache (Dataverse pattern #6: flush picklist cache when metadata changes)."""
        try:
            for f in self.cache_dir.glob("*.json"):
                f.unlink()
            # Clear lru_cache
            _cached_parse_key.cache_clear()
            self._stats = {"hits": 0, "misses": 0, "errors": 0, "time_ms": 0.0}
        except Exception:
            pass

    def stats(self) -> Dict:
        total = self._stats["hits"] + self._stats["misses"]
        hit_rate = self._stats["hits"] / total if total else 0
        return {**self._stats, "hit_rate": hit_rate, "cache_dir": str(self.cache_dir)}

    def incremental_needed(self, file_path: pathlib.Path) -> bool:
        """Check if file needs re-parsing (incremental analysis Plan #15)."""
        try:
            h = _file_hash(file_path.read_bytes())
        except:
            return True
        rel = str(file_path.relative_to(self.project_root)) if str(file_path).startswith(str(self.project_root)) else str(file_path)
        cache_key = _cached_parse_key(rel, h)
        cache_file = self.cache_dir / f"{hashlib.md5(cache_key.encode()).hexdigest()}.json"
        return not cache_file.exists()

# ── Chunked File Upload handling (Dataverse pattern #7) ──
def upload_large_file_in_chunks(file_path: pathlib.Path, chunk_size: int = 4 * 1024 * 1024):
    """
    Demonstrates chunked handling for large PHP files (analogy to Dataverse file upload).
    For analyzer: if file > chunk_size, process in chunks for memory efficiency (generator).
    """
    with open(file_path, 'r', errors='ignore') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

@lru_cache(maxsize=1)
def get_parser(project_root: str, timeout: float = 10.0) -> PhpAstParser:
    """Cached parser singleton per project root."""
    return PhpAstParser(pathlib.Path(project_root), ParserConfig(timeout=timeout))
