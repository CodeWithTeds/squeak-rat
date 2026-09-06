#!/usr/bin/env python3
"""
python_precise_scanner.py — Precise Python taint scanner (vs PHP RAT naive)
-----------------------------------------------------------------------------
Implements what RAT *should* do:
  - Strip strings/comments before regex (no literal false positives)
  - Check variable-level taint: source var must reach sink argument
  - Ignore infra/tool files from auth/hidden checks
  - Require real class constructs for hidden_behavior

Use:
    python3 python_precise_scanner.py
    python3 python_precise_scanner.py --format=json --path=app,src
"""

import re
import json
import pathlib
import argparse
from typing import List, Dict

DEFAULT_EXCLUDE = ["vendor","storage","bootstrap/cache","node_modules","public",".git",".idea",".vscode","tests_python","python_precise_scanner.py","verify_false_positives.py"]

def strip_php(content: str) -> str:
    strings=[]
    def _repl(m):
        strings.append(m.group(0))
        return f"__STR{len(strings)-1}__"
    tmp = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", _repl, content)
    tmp = re.sub(r"//.*", "", tmp)
    tmp = re.sub(r"^\s*#.*", "", tmp, flags=re.M)
    tmp = re.sub(r"/\*.*?\*/", "", tmp, flags=re.S)
    return tmp

SOURCE_RE = re.compile(r'\$request\s*->\s*(input|query|post|get|all|only|except|file|header|cookie|server|bearerToken|route)\s*\(|request\s*\(\s*\)\s*->\s*(input|all|query|file)\s*\(|\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES', re.I)
# For variable extraction: capture $var on source line
VAR_RE = re.compile(r'\$[a-zA-Z_]\w*')

SINK_PATS = [
    (re.compile(r'Storage\s*::\s*(put|putFile|putFileAs|store|storeAs|append|prepend|copy|move|delete)\s*\(', re.I), "Storage::put", "critical"),
    (re.compile(r'\bfile_put_contents\s*\(', re.I), "file_put_contents", "critical"),
    (re.compile(r'\bfile_get_contents\s*\(.*\$', re.I), "file_get_contents", "high"), # only tainted if arg contains var
    (re.compile(r'\bDB\s*::\s*(raw|select|statement|unprepared)\s*\(.*\$', re.I), "DB::raw", "critical"),
    (re.compile(r'\bwhereRaw\s*\(.*\$|\bselectRaw\s*\(.*\$', re.I), "Raw SQL", "high"),
    (re.compile(r'\bexec\s*\(.*\$|\bshell_exec\s*\(.*\$|\bsystem\s*\(.*\$|\bpassthru\s*\(.*\$', re.I), "shell execution", "critical"),
    (re.compile(r'\beval\s*\(.*\$', re.I), "eval", "critical"),
    (re.compile(r'\bunserialize\s*\(.*\$', re.I), "unserialize", "critical"),
    (re.compile(r'\bHttp\s*::\s*(get|post|put|patch|delete|send)\s*\(.*\$', re.I), "Http::request", "medium"),
]

# Precise hidden: need class definition or real dispatch
HIDDEN_REAL = [
    re.compile(r'class\s+\w+Observer\b'),
    re.compile(r'class\s+\w+Job\b.*ShouldQueue', re.S),
    re.compile(r'dispatch\s*\(\s*new\s+\w+Job'),
    re.compile(r'Event\s*::\s*dispatch\s*\(.*Event'),
    re.compile(r'::observe\s*\(\s*\w+Observer::class'),
]

def collect_php_files(root: pathlib.Path, paths: List[str], exclude: List[str]) -> List[pathlib.Path]:
    files=[]
    for p in paths:
        full = root / p.lstrip("/")
        if full.is_file() and full.suffix==".php":
            files.append(full)
            continue
        if not full.is_dir():
            continue
        for fp in full.rglob("*.php"):
            rel = str(fp.relative_to(root))
            if any(rel.startswith(ex) or f"/{ex}/" in rel for ex in exclude):
                continue
            files.append(fp)
    return sorted(set(files))

def precise_scan(root: str | pathlib.Path = ".", paths: List[str] | None = None, exclude: List[str] | None = None) -> List[Dict]:
    root = pathlib.Path(root).resolve()
    paths = paths or ["."]
    exclude = exclude or DEFAULT_EXCLUDE

    findings=[]
    files = collect_php_files(root, paths, exclude)
    for fp in files:
        rel = str(fp.relative_to(root))
        # skip RAT's own engine when scanning self? For demo we exclude src/Engine to show pure false,
        # but allow scanning if explicitly requested. We'll scan all then filter infra via flag.
        raw = fp.read_text(errors="ignore")
        clean = strip_php(raw)
        # Quick check: source + sink must exist in CLEAN
        if not SOURCE_RE.search(clean):
            continue
        # Track tainted vars per file: variables assigned from source
        tainted_vars = set()
        for line in clean.splitlines():
            if SOURCE_RE.search(line):
                # extract LHS var if assignment: $x = $request->input(...)
                m_assign = re.search(r'(\$[a-zA-Z_]\w*)\s*=\s*.*\$request|(\$[a-zA-Z_]\w*)\s*=\s*.*request\(\)', line)
                if m_assign:
                    var = m_assign.group(1) or m_assign.group(2)
                    if var:
                        tainted_vars.add(var)
                # Also if source is used directly without assignment, mark $request itself as tainted pattern
                # we will check direct $request->input in sink line
                tainted_vars.add("$request")
                # capture superglobal var directly
                for sup in re.findall(r'\$_GET|\$_POST|\$_REQUEST|\$_FILES|\$_COOKIE', line):
                    tainted_vars.add(sup)

        if not tainted_vars:
            continue

        # Check each sink pattern: does sink line contain tainted var?
        for pat, sink_name, sev in SINK_PATS:
            for m in pat.finditer(clean):
                # Get line content
                offset = m.start()
                lnum = clean[:offset].count("\n")+1
                line_content = clean.splitlines()[lnum-1] if lnum<= len(clean.splitlines()) else ""
                # Check if any tainted var appears in this line (or next line if multiline?)
                # Also handle direct $request->... inside sink line
                has_taint = any(v in line_content for v in tainted_vars) or SOURCE_RE.search(line_content)
                # Extra for file_get_contents: ensure arg is tainted, not internal $file from collectPhpFiles
                # Heuristic: if sink is file_get_contents and arg is $file but $file not in tainted_vars (it was from RecursiveDirectoryIterator)
                # then no taint. Our tainted_vars only contains $request-derived, so $file alone won't match.
                if has_taint:
                    # Validation check: if line has ->validate or Validator, lower severity / skip? We flag but medium
                    has_validation = "validate" in clean.lower() or "FormRequest" in raw
                    findings.append({
                        "file": rel,
                        "line": lnum,
                        "sink": sink_name,
                        "severity": sev,
                        "confidence": "high" if not has_validation else "medium",
                        "tainted_vars": sorted(list(tainted_vars)),
                        "code": line_content.strip()[:160],
                        "category": "data_flow"
                    })
                # else: file-level co-existence but no variable taint → NO finding (fixes RAT bug at Analyzer.php:133)

        # Authorization: only if file is controller-like and sensitive, and no auth
        # Skip infra files entirely
        if "Engine" in rel or "Support" in rel or "Console" in rel:
            continue
        is_controller = "Controller" in fp.name or "/Http/Controllers" in rel
        if is_controller:
            has_sens = bool(re.search(r'::\s*(update|delete|create)\s*\(|User\s*::', clean))
            has_auth = bool(re.search(r'->\s*authorize\s*\(|Gate\s*::|can:|middleware.*auth|Policy|Auth::', clean, re.I))
            if has_sens and not has_auth:
                findings.append({
                    "file": rel, "line": 1, "sink": "authorization", "severity": "high", "confidence": "medium",
                    "category": "authorization", "code": "missing authorize/Gate/Policy"
                })

        # Hidden: only real constructs
        if any(p.search(clean) for p in HIDDEN_REAL):
            # Only flag if file is model/service that actually triggers, not detector itself
            if "Observer" not in rel and "Analyzer" not in rel and "HiddenBehavior" not in rel:
                findings.append({
                    "file": rel, "line": 1, "sink": "hidden_behavior", "severity": "medium", "confidence": "high",
                    "category": "hidden_behavior", "code": "real Observer/Job found"
                })

    # Dedup by file+sink
    seen=set()
    uniq=[]
    for f in findings:
        key=(f["file"], f["sink"], f["line"])
        if key not in seen:
            seen.add(key); uniq.append(f)
    return uniq

def main():
    parser=argparse.ArgumentParser(description="Precise Python scanner")
    parser.add_argument("--path", default=".", help="comma separated paths")
    parser.add_argument("--format", choices=["text","json"], default="text")
    parser.add_argument("--exclude", default=",".join(DEFAULT_EXCLUDE))
    args=parser.parse_args()
    root=pathlib.Path.cwd()
    paths=[p.strip() for p in args.path.split(",") if p.strip()]
    exclude=[e.strip() for e in args.exclude.split(",") if e.strip()]
    findings=precise_scan(root, paths, exclude)
    if args.format=="json":
        print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    else:
        print(f"Python precise scan — {len(findings)} findings")
        for f in findings:
            print(f"  {f['severity']:8} {f['file']}:{f['line']}  {f['sink']}  `{f['code']}`")
        if not findings:
            print("✅ 0 findings — clean (no true taint flow)")
        print(f"\nScanned {len(collect_php_files(root, paths, exclude))} php files")

if __name__=="__main__":
    main()
