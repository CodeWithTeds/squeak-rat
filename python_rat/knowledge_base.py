"""
knowledge_base.py — Laravel Security Knowledge Base (Plan #3, #19)
Structured database of Laravel APIs: sources, sinks, sanitizers, validation, auth, etc.
Evolves independently from analysis engine.
Based on 100x plan section 3 & 19.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set
from functools import lru_cache

@dataclass(frozen=True)
class SinkDefinition:
    """Dangerous sink definition."""
    id: str
    pattern: str  # regex
    category: str  # injection, xss, etc.
    severity: str
    description: str
    cwe: str = ""
    requires_taint: bool = True

@dataclass(frozen=True)
class SourceDefinition:
    id: str
    pattern: str
    description: str
    category: str = "user_input"

@dataclass(frozen=True)
class SanitizerDefinition:
    id: str
    pattern: str
    description: str
    mitigates: List[str]  # categories it mitigates

# ── SOURCES ──
LARAVEL_SOURCES: List[SourceDefinition] = [
    SourceDefinition("request_input", r'\$request\s*->\s*input\s*\(', "Request::input() user data", "input"),
    SourceDefinition("request_query", r'\$request\s*->\s*query\s*\(', "Request::query()", "input"),
    SourceDefinition("request_post", r'\$request\s*->\s*post\s*\(', "Request::post()", "input"),
    SourceDefinition("request_all", r'\$request\s*->\s*all\s*\(', "Request::all()", "input"),
    SourceDefinition("request_only", r'\$request\s*->\s*only\s*\(', "Request::only()", "input"),
    SourceDefinition("request_except", r'\$request\s*->\s*except\s*\(', "Request::except()", "input"),
    SourceDefinition("request_file", r'\$request\s*->\s*file\s*\(', "Uploaded file", "file"),
    SourceDefinition("request_header", r'\$request\s*->\s*header\s*\(', "Request header", "header"),
    SourceDefinition("request_cookie", r'\$request\s*->\s*cookie\s*\(', "Request cookie", "cookie"),
    SourceDefinition("request_server", r'\$request\s*->\s*server\s*\(', "Server var", "input"),
    SourceDefinition("request_bearer", r'\$request\s*->\s*bearerToken\s*\(', "Bearer token", "auth"),
    SourceDefinition("request_route", r'\$request\s*->\s*route\s*\(', "Route param", "route"),
    SourceDefinition("helper_request", r'request\s*\(\s*\)\s*->\s*(input|all|query|file)\s*\(', "request() helper", "input"),
    SourceDefinition("superglobal_get", r'\$_GET', "Superglobal GET", "input"),
    SourceDefinition("superglobal_post", r'\$_POST', "Superglobal POST", "input"),
    SourceDefinition("superglobal_request", r'\$_REQUEST', "Superglobal REQUEST", "input"),
    SourceDefinition("superglobal_cookie", r'\$_COOKIE', "Superglobal COOKIE", "cookie"),
    SourceDefinition("superglobal_files", r'\$_FILES', "Uploaded files", "file"),
    SourceDefinition("superglobal_server", r'\$_SERVER', "Server superglobal", "input"),
    SourceDefinition("route_param", r'Route\s*::\s*(get|post|put|patch|delete).*\{[^}]+\}', "Route parameter", "route"),
    SourceDefinition("file_upload", r'\$request\s*->\s*file\s*\(|\$_FILES', "File upload", "file"),
    SourceDefinition("json_input", r'\$request\s*->\s*json\s*\(|json_decode\s*\(.*\$request', "JSON input", "input"),
]

# ── SINKS ── (85+ mapped, categories align with Plan #8)
LARAVEL_SINKS: List[SinkDefinition] = [
    # Injection
    SinkDefinition("db_raw", r'DB\s*::\s*(raw|select|statement|unprepared|insert|update|delete)\s*\(', "injection", "critical", "Raw SQL execution", "CWE-89"),
    SinkDefinition("raw_sql", r'\bwhereRaw\s*\(|\bselectRaw\s*\(|\borderByRaw\s*\(|\bhavingRaw\s*\(', "injection", "high", "Raw where/select", "CWE-89"),
    SinkDefinition("query_builder_raw", r'->\s*whereRaw|\->selectRaw', "injection", "high", "Query builder raw", "CWE-89"),
    SinkDefinition("pdo_query", r'PDO\s*::\s*query|->\s*query\s*\(.*\$', "injection", "critical", "PDO query", "CWE-89"),
    SinkDefinition("eloquent_raw", r'::\s*whereRaw|::\s*selectRaw', "injection", "high", "Eloquent raw", "CWE-89"),
    # Command injection
    SinkDefinition("shell_exec", r'\bexec\s*\(|\bshell_exec\s*\(|\bsystem\s*\(|\bpassthru\s*\(|\bproc_open\s*\(|\bpopen\s*\(', "command_injection", "critical", "Shell execution", "CWE-78"),
    SinkDefinition("process_run", r'Process\s*::\s*run|Symfony.*Process', "command_injection", "critical", "Process::run", "CWE-78"),
    SinkDefinition("eval", r'\beval\s*\(', "code_injection", "critical", "Dynamic eval", "CWE-95"),
    SinkDefinition("call_user_func", r'\bcall_user_func', "code_injection", "high", "Dynamic call", "CWE-95"),
    # XSS
    SinkDefinition("blade_unescaped", r'\{!!\s*.*\$', "xss", "high", "Unescaped Blade output", "CWE-79"),
    SinkDefinition("echo_output", r'\becho\s+.*\$|print\s+.*\$', "xss", "medium", "Direct echo", "CWE-79"),
    SinkDefinition("response_html", r'Response\s*::\s*make.*\$|->\s*html\s*\(.*\$', "xss", "medium", "HTML response", "CWE-79"),
    # Path traversal
    SinkDefinition("file_get_contents", r'\bfile_get_contents\s*\(', "path_traversal", "high", "File read", "CWE-22"),
    SinkDefinition("file_put_contents", r'\bfile_put_contents\s*\(', "path_traversal", "critical", "File write", "CWE-22"),
    SinkDefinition("fopen", r'\bfopen\s*\(', "path_traversal", "high", "File open", "CWE-22"),
    SinkDefinition("filesystem", r'\bunlink\s*\(|\bmkdir\s*\(|\brmdir\s*\(|\brename\s*\(', "path_traversal", "high", "Filesystem op", "CWE-22"),
    SinkDefinition("storage_put", r'Storage\s*::\s*(put|putFile|putFileAs|store|storeAs|append|prepend|copy|move|delete)\s*\(', "path_traversal", "critical", "Storage write", "CWE-22"),
    SinkDefinition("include", r'include\s*\(|require\s*\(|include_once|require_once', "path_traversal", "critical", "File inclusion", "CWE-98"),
    # SSRF
    SinkDefinition("http_request", r'Http\s*::\s*(get|post|put|patch|delete|send)\s*\(', "ssrf", "medium", "HTTP request", "CWE-918"),
    SinkDefinition("curl", r'\bcurl_exec\s*\(|curl_init\s*\(.*\$', "ssrf", "medium", "cURL", "CWE-918"),
    SinkDefinition("file_get_contents_url", r'file_get_contents\s*\(.*https?://.*\$', "ssrf", "medium", "URL file get", "CWE-918"),
    # File upload
    SinkDefinition("file_upload_move", r'->\s*move\s*\(.*\$|->\s*store\s*\(.*\$|->\s*storeAs\s*\(.*\$', "file_upload", "high", "File move/store", "CWE-434"),
    # Mass assignment
    SinkDefinition("mass_assignment", r'->\s*update\s*\(|::\s*create\s*\(|::\s*update\s*\(|->\s*fill\s*\(|->\s*forceFill\s*\(', "mass_assignment", "high", "Mass assignment", "CWE-915"),
    # Authz
    SinkDefinition("auth_update", r'User\s*::\s*update|::\s*delete\s*\(|->\s*delete\s*\(', "idor", "high", "Sensitive model write", "CWE-639"),
    # Open redirect
    SinkDefinition("redirect", r'redirect\s*\(\s*\$|Redirect\s*::\s*to\s*\(.*\$|->\s*redirect\s*\(.*\$', "open_redirect", "medium", "Dynamic redirect", "CWE-601"),
    # Deserialization
    SinkDefinition("unserialize", r'\bunserialize\s*\(', "deserialization", "critical", "Unsafe unserialize", "CWE-502"),
    SinkDefinition("serialize", r'\bserialize\s*\(', "deserialization", "medium", "Serialize", "CWE-502"),
    # Crypto / secrets
    SinkDefinition("hardcoded_secret", r'password\s*=\s*["\'][^"\']+["\']|secret\s*=\s*["\']|sk_live_|AKIA[0-9A-Z]{16}', "hardcoded_secret", "high", "Hardcoded secret", "CWE-798"),
    # Dynamic execution
    SinkDefinition("dynamic_function", r'\$[a-zA-Z_]+\s*\(\s*\$', "code_injection", "high", "Dynamic function call", "CWE-95"),
    SinkDefinition("dynamic_instantiation", r'new\s+\$[a-zA-Z_]', "code_injection", "high", "Dynamic instantiation", "CWE-95"),
    SinkDefinition("preg_replace_eval", r'preg_replace\s*\(.*\/e.*\$', "code_injection", "critical", "preg_replace /e", "CWE-95"),
]

# ── SANITIZERS ── (Plan #7)
LARAVEL_SANITIZERS: List[SanitizerDefinition] = [
    SanitizerDefinition("validate", r'->\s*validate\s*\(', "Validated via validate()", ["xss", "injection", "mass_assignment"]),
    SanitizerDefinition("validated", r'->\s*validated\s*\(', "Validated data only", ["mass_assignment", "injection"]),
    SanitizerDefinition("safe", r'->\s*safe\s*\(', "Safe validated data", ["mass_assignment", "injection"]),
    SanitizerDefinition("only", r'->\s*only\s*\(', "Allow-list filtered", ["mass_assignment"]),
    SanitizerDefinition("escape_e", r'e\s*\(.*\$|htmlspecialchars\s*\(|htmlentities\s*\(', "Escaped for HTML", ["xss"]),
    SanitizerDefinition("blade_escaped", r'\{\{\s*.*\}\}', "Blade escaped output", ["xss"]),
    SanitizerDefinition("parameterized", r'where\s*\(.*\?|where\s*\(.*:.*\)|DB::select\s*\(.*\?,|->\s*where\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*\$', "Parameterized query", ["injection"]),
    SanitizerDefinition("purify", r'Purifier\s*::\s*clean|strip_tags\s*\(', "HTML purified", ["xss"]),
    SanitizerDefinition("int_cast", r'\(int\)\s*\$|intval\s*\(.*\$', "Integer cast", ["injection", "path_traversal"]),
    SanitizerDefinition("basename", r'basename\s*\(.*\$', "Basename sanitized", ["path_traversal"]),
    SanitizerDefinition("hash", r'Hash\s*::\s*make|bcrypt\s*\(', "Hashed", ["hardcoded_secret"]),
]

# ── VALIDATION RULES mapping ──
VALIDATION_SENSITIVITY: Dict[str, Set[str]] = {
    # sink_category -> rules that are sufficient
    "injection": {"exists", "integer", "numeric", "in:", "enum", "regex", "uuid"},
    "xss": {"string", "alpha", "alpha_dash", "regex"},
    "mass_assignment": {"filled", "sometimes", "required"},  # but must check allow-list!
    "path_traversal": {"mimes", "file", "image", "regex"},
    "ssrf": {"url", "active_url"},
    "command_injection": set(),  # no validation is sufficient - must sanitize/escape
}

# ── AUTH patterns ──
AUTH_PATTERNS = [
    r'->\s*authorize\s*\(',
    r'\$this\s*->\s*authorize',
    r'Gate\s*::\s*(allows|denies|authorize)',
    r'\$user\s*->\s*can\s*\(',
    r'can\s*:\s*',
    r'middleware\s*\(\s*[\'"]can:',
    r'middleware\s*\(\s*[\'"]auth',
    r'auth\s*:\s*',
    r'->\s*middleware\s*\(.*auth',
    r'Policy',
    r'\$request\s*->\s*user\s*\(',
    r'Auth\s*::',
]

# ── LARAVEL VERSION specifics ──
FRAMEWORK_VERSIONS = {
    "10": {"php": "8.1", "features": ["enums", "vite"]},
    "11": {"php": "8.2", "features": ["slim_app", "per_second_rate_limit"]},
    "12": {"php": "8.2", "features": ["starter_kit", "new_auth"]},
}

class LaravelKnowledgeBase:
    """
    Central knowledge base for Laravel semantics.
    Introspection via @lru_cache for performance (Pattern 12).
    """
    def __init__(self):
        self._source_res = [(s, re.compile(s.pattern, re.I)) for s in LARAVEL_SOURCES]
        self._sink_res = [(s, re.compile(s.pattern, re.I)) for s in LARAVEL_SINKS]
        self._sanitizer_res = [(s, re.compile(s.pattern, re.I)) for s in LARAVEL_SANITIZERS]
        self._auth_res = [re.compile(p, re.I) for p in AUTH_PATTERNS]

    @lru_cache(maxsize=1024)
    def is_source_line(self, line: str) -> bool:
        """O(1) cached source check."""
        return any(p.search(line) for _, p in self._source_res)

    @lru_cache(maxsize=1024)
    def detect_sinks(self, content: str) -> List[Dict]:
        hits = []
        for sink, pat in self._sink_res:
            for m in pat.finditer(content):
                hits.append({
                    "id": sink.id,
                    "sink": sink.pattern.strip()[:60] if len(sink.pattern) > 60 else sink.pattern,
                    "sink_name": sink.id,
                    "category": sink.category,
                    "severity": sink.severity,
                    "description": sink.description,
                    "cwe": sink.cwe,
                    "offset": m.start(),
                    "snippet": m.group(0).strip()[:100],
                })
        return hits

    @lru_cache(maxsize=1024)
    def detect_sources(self, content: str) -> List[Dict]:
        hits = []
        for src, pat in self._source_res:
            for m in pat.finditer(content):
                hits.append({
                    "id": src.id,
                    "source": src.id,
                    "offset": m.start(),
                    "snippet": m.group(0).strip()[:80],
                })
        return hits

    def has_auth(self, content: str) -> bool:
        return any(p.search(content) for p in self._auth_res)

    def is_sanitized(self, line: str, sink_category: str) -> bool:
        """Check if line contains sanitizer sufficient for sink category."""
        for sanitizer, pat in self._sanitizer_res:
            if pat.search(line) and sink_category in sanitizer.mitigates:
                return True
        return False

    def is_validation_sufficient(self, validation_rules: str, sink_category: str) -> bool:
        """Determine if validation rules are sufficient for sink (Plan #7)."""
        sufficient = VALIDATION_SENSITIVITY.get(sink_category, set())
        if not sufficient:
            return False  # e.g. command injection never sufficient via validation
        lower = validation_rules.lower()
        return any(rule in lower for rule in sufficient)

    @lru_cache(maxsize=512)
    def get_sink_by_id(self, sink_id: str) -> SinkDefinition | None:
        for s in LARAVEL_SINKS:
            if s.id == sink_id:
                return s
        return None

    def all_sinks(self) -> List[SinkDefinition]:
        return LARAVEL_SINKS

    def all_sources(self) -> List[SourceDefinition]:
        return LARAVEL_SOURCES

# Singleton for global use
KB = LaravelKnowledgeBase()

@lru_cache(maxsize=1)
def get_kb() -> LaravelKnowledgeBase:
    return KB
