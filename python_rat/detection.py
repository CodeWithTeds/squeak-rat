import re
from typing import Dict, List, Tuple

# ------------------------------------------------------------------
# Precise SourceDetector — runs on stripped code (no strings/comments)
# ------------------------------------------------------------------
SOURCE_PATS = [
    re.compile(r'\$request\s*->\s*(input|query|post|get|all|only|except|file|header|cookie|server|bearerToken|route)\s*\(', re.I),
    re.compile(r'request\s*\(\s*\)\s*->\s*(input|all|query|file)\s*\(', re.I),
    re.compile(r'\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES', re.I),
]

SINK_PATS = [
    (re.compile(r'Storage\s*::\s*(put|putFile|putFileAs|store|storeAs|append|prepend|copy|move|delete)\s*\(', re.I), "Storage::put", "critical"),
    (re.compile(r'\bfile_put_contents\s*\(', re.I), "file_put_contents", "critical"),
    (re.compile(r'\bfile_get_contents\s*\(', re.I), "file_get_contents", "high"),
    (re.compile(r'\bfopen\s*\(', re.I), "fopen", "high"),
    (re.compile(r'\bunlink\s*\(|\bmkdir\s*\(|\brmdir\s*\(|\brename\s*\(', re.I), "filesystem operation", "high"),
    (re.compile(r'include\s*\(|require\s*\(|include_once|require_once', re.I), "file inclusion", "critical"),
    (re.compile(r'DB\s*::\s*(raw|select|statement|unprepared|insert|update|delete)\s*\(', re.I), "DB::raw", "critical"),
    (re.compile(r'\bwhereRaw\s*\(|\bselectRaw\s*\(|\borderByRaw\s*\(|\bhavingRaw\s*\(', re.I), "Raw SQL", "high"),
    (re.compile(r'\bexec\s*\(|\bshell_exec\s*\(|\bsystem\s*\(|\bpassthru\s*\(|\bproc_open\s*\(|\bpopen\s*\(', re.I), "shell execution", "critical"),
    (re.compile(r'Process\s*::\s*run|Symfony.*Process', re.I), "Process::run", "critical"),
    (re.compile(r'Http\s*::\s*(get|post|put|patch|delete|send)\s*\(', re.I), "Http::request", "medium"),
    (re.compile(r'\beval\s*\(', re.I), "eval", "critical"),
    (re.compile(r'\bcall_user_func', re.I), "call_user_func", "high"),
    (re.compile(r'new\s+\$[a-zA-Z_]', re.I), "dynamic class instantiation", "high"),
    (re.compile(r'\$[a-zA-Z_]+\s*\(\s*\$', re.I), "dynamic function call", "high"),
    (re.compile(r'redirect\s*\(\s*\$|Redirect\s*::\s*to\s*\(.*\$', re.I), "dynamic redirect", "medium"),
    (re.compile(r'\bunserialize\s*\(', re.I), "unserialize", "critical"),
    (re.compile(r'\bserialize\s*\(', re.I), "serialize", "medium"),
    # mass assignment: require ->update or ::create/::update (not function definition)
    (re.compile(r'->\s*update\s*\(|::\s*create\s*\(|::\s*update\s*\(', re.I), "mass assignment", "high"),
]

AUTH_PATS = [re.compile(p, re.I) for p in [
    r'->\s*authorize\s*\(', r'\$this\s*->\s*authorize', r'Gate\s*::\s*(allows|denies|authorize)', r'\$user\s*->\s*can\s*\(', r'can\s*:\s*', r'middleware\s*\(\s*[\'"]can:', r'middleware\s*\(\s*[\'"]auth', r'auth\s*:\s*', r'->\s*middleware\s*\(.*auth', r'Policy', r'\$request\s*->\s*user\s*\(', r'Auth\s*::'
]]

SENSITIVE_PATS = [re.compile(p, re.I) for p in [
    r'::\s*update\s*\(', r'::\s*delete\s*\(', r'::\s*create\s*\(', r'User\s*::', r'->\s*delete\s*\(', r'\badmin\b'
]]

class SourceDetector:
    @staticmethod
    def detect(content_clean: str) -> List[Tuple[str,int]]:
        hits=[]
        for pat in SOURCE_PATS:
            for m in pat.finditer(content_clean):
                hits.append((m.group(0).strip()[:80], m.start()))
        return hits

    @staticmethod
    def is_source_line(line_clean: str) -> bool:
        return any(p.search(line_clean) for p in SOURCE_PATS)

class SinkDetector:
    @staticmethod
    def detect(content_clean: str):
        hits=[]
        for pat, sink, sev in SINK_PATS:
            for m in pat.finditer(content_clean):
                hits.append({"snippet": m.group(0).strip()[:100], "sink": sink, "severity": sev, "offset": m.start()})
        return hits

class AuthorizationAnalyzer:
    @staticmethod
    def has_auth(content_clean: str) -> bool:
        return any(p.search(content_clean) for p in AUTH_PATS)
    @staticmethod
    def is_sensitive(content_clean: str) -> bool:
        return any(p.search(content_clean) for p in SENSITIVE_PATS)

class HiddenBehaviorAnalyzerPrecise:
    # Precise patterns: require class definitions / queued jobs, not explicit Mail::send (fixed RAT-001/002 false hidden)
    PATTERNS = {
        'observer': re.compile(r'class\s+\w+Observer\b|::observe\s*\(\s*\w+Observer::class', re.I),
        'event': re.compile(r'class\s+\w+Event\b|Event\s*::\s*dispatch', re.I),
        'listener': re.compile(r'class\s+\w+Listener\b', re.I),
        'job': re.compile(r'class\s+\w+Job\b.*ShouldQueue|dispatch\s*\(\s*new\s+\w+Job', re.I | re.S),
        'notification': re.compile(r'class\s+\w+Notification\b', re.I),
        'mail': re.compile(r'class\s+\w+Mailable\b', re.I),
        'model_event': re.compile(r'::\s*created\b|::\s*updated\b|::\s*saved\b|::\s*deleted\b|booted|observe\s*\(', re.I),
    }
    @staticmethod
    def analyze(content_clean: str) -> Dict[str, list]:
        found={}
        for k, pat in HiddenBehaviorAnalyzerPrecise.PATTERNS.items():
            if pat.search(content_clean):
                found[k]=True
        return found
    @staticmethod
    def has_hidden(content_clean: str) -> bool:
        return bool(HiddenBehaviorAnalyzerPrecise.analyze(content_clean))

# Naive versions for comparison / false-positive demo (run on raw) — not used for precise findings
class SourceDetectorNaive:
    PATTS = [r'\$request\s*->\s*(input|query|post|get|all|only|except|file|header|cookie|server|bearerToken)\s*\(', r'request\s*\(\s*\)\s*->\s*(input|all|query|file)\s*\(', r'\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES']
