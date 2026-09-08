"""
rules/__init__.py — Rule Engine (Plan #14) + Separate generic vs project rules (Plan #13)
Each rule defines: ID, Name, Description, Severity, Sources, Sinks, Sanitizers, Detection logic, Confidence, Remediation.

Architecture per plan:
  rules/
    laravel/
      sql_injection.py, xss.py, authorization.py, idor.py, file_upload.py
    project/
      custom_rules.py
"""
from __future__ import annotations
import re
import pathlib
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional
from abc import ABC, abstractmethod
from functools import lru_cache

@dataclass(frozen=True)
class RuleMeta:
    id: str
    name: str
    description: str
    severity: str
    category: str
    cwe: str
    confidence: str = "high"

@dataclass
class FindingEvidence:
    rule_id: str
    severity: str
    confidence: str
    source: str
    sink: str
    file: str
    line: int
    flow: List[str]
    message: str
    remediation: str
    category: str
    why: str

class SecurityRule(ABC):
    """Abstract rule interface (Plan #14)."""
    @property
    @abstractmethod
    def meta(self) -> RuleMeta:
        ...

    @property
    @abstractmethod
    def sources(self) -> List[str]:
        """Source patterns this rule cares about."""
        ...

    @property
    @abstractmethod
    def sinks(self) -> List[str]:
        ...

    @property
    @abstractmethod
    def sanitizers(self) -> List[str]:
        ...

    @abstractmethod
    def detect(self, content: str, file_path: str, taint_flow=None) -> List[FindingEvidence]:
        """Detection logic → evidence with confidence."""
        ...

    def confidence_for(self, has_validation: bool, sanitized: bool, tainted: bool) -> str:
        if not tainted:
            return "low"
        if sanitized:
            return "low"
        if has_validation:
            return "medium"
        return self.meta.confidence

# ── Concrete Laravel Rules (Plan #8) ──
class SqlInjectionRule(SecurityRule):
    @property
    def meta(self):
        return RuleMeta("LARAVEL-SQL-001", "SQL Injection", "User input reaches raw SQL without parameterization", "critical", "injection", "CWE-89")
    @property
    def sources(self): return [r'\$request->.*input', r'\$_GET|\$_POST']
    @property
    def sinks(self): return [r'DB::raw', r'whereRaw', r'selectRaw']
    @property
    def sanitizers(self): return [r'\?', r'where\(.*\?', r'parameterized']
    def detect(self, content: str, file_path: str, taint_flow=None):
        if taint_flow and taint_flow.sink_category == "injection" and taint_flow.sink == "db_raw":
            return [FindingEvidence(
                rule_id=self.meta.id, severity=self.meta.severity, confidence=taint_flow.confidence,
                source=taint_flow.source, sink=taint_flow.sink, file=taint_flow.sink_file, line=taint_flow.sink_line,
                flow=taint_flow.path, message=f"SQL injection: {taint_flow.source} reaches {taint_flow.sink} in {file_path}:{taint_flow.sink_line}",
                remediation="Use parameterized queries: ->where('col', $value) or DB::select('select * where id = ?', [$id])", category="injection",
                why=f"User-controlled data originates from {taint_flow.source} and reaches DB::raw without parameterization. Flow: {' -> '.join(taint_flow.path)}"
            )]
        return []

class XssRule(SecurityRule):
    @property
    def meta(self):
        return RuleMeta("LARAVEL-XSS-001", "Cross-Site Scripting", "User input reaches HTML output without escaping", "high", "xss", "CWE-79")
    @property
    def sources(self): return [r'\$request->.*']
    @property
    def sinks(self): return [r'\{!!', r'echo.*\$', r'->html\(']
    @property
    def sanitizers(self): return [r'e\(.*\$', r'htmlspecialchars', r'\{\{.*\}\}']
    def detect(self, content, file_path, taint_flow=None):
        if taint_flow and taint_flow.sink_category == "xss":
            return [FindingEvidence(self.meta.id, self.meta.severity, taint_flow.confidence, taint_flow.source, taint_flow.sink, taint_flow.sink_file, taint_flow.sink_line, taint_flow.path,
                f"XSS: {taint_flow.source} reaches unescaped output in {file_path}:{taint_flow.sink_line}",
                "Escape with {{ $var }} (Blade) or e($var) or Purifier::clean()", "xss",
                "Blade escaping requires {{ }}; {!! !!} is unescaped. Check if output is escaped.")]
        return []

class CommandInjectionRule(SecurityRule):
    @property
    def meta(self): return RuleMeta("LARAVEL-CMD-001", "Command Injection", "User input reaches shell execution", "critical", "command_injection", "CWE-78")
    @property
    def sources(self): return [r'\$request->.*']
    @property
    def sinks(self): return [r'exec\(|shell_exec|system|passthru|proc_open']
    @property
    def sanitizers(self): return [r'escapeshellarg|escapeshellcmd']
    def detect(self, content, file_path, taint_flow=None):
        if taint_flow and taint_flow.sink_category == "command_injection":
            return [FindingEvidence(self.meta.id, self.meta.severity, taint_flow.confidence, taint_flow.source, taint_flow.sink, file_path, taint_flow.sink_line, taint_flow.path,
                f"Command injection: {taint_flow.source} reaches shell in {file_path}:{taint_flow.sink_line}", "Use escapeshellarg(), avoid shell, use Process with array args", "command_injection",
                "Shell execution with user data enables RCE. Use array-based Process or escapeshellarg.")]
        return []

class PathTraversalRule(SecurityRule):
    @property
    def meta(self): return RuleMeta("LARAVEL-PT-001", "Path Traversal", "User input reaches filesystem path without sanitization", "high", "path_traversal", "CWE-22")
    @property
    def sources(self): return [r'\$request->file\(|.*filename']
    @property
    def sinks(self): return [r'Storage::put|file_get_contents|file_put_contents|fopen']
    @property
    def sanitizers(self): return [r'basename\(|store\(|storeAs|hashName']
    def detect(self, content, file_path, taint_flow=None):
        if taint_flow and taint_flow.sink_category == "path_traversal":
            # Check if using store() (sanitized) vs put with user path
            if "store(" in taint_flow.evidence[0] if taint_flow.evidence else False:
                return []
            return [FindingEvidence(self.meta.id, self.meta.severity, taint_flow.confidence, taint_flow.source, taint_flow.sink, file_path, taint_flow.sink_line, taint_flow.path,
                f"Path traversal: {taint_flow.source} reaches {taint_flow.sink}", "Validate filename, use basename(), store() with hashed names, allow-list extensions", "path_traversal",
                "Filesystem path from user can read/write arbitrary files. Use storage with hashed names.")]
        return []

class SsrfRule(SecurityRule):
    @property
    def meta(self): return RuleMeta("LARAVEL-SSRF-001", "Server-Side Request Forgery", "User input reaches HTTP request URL", "medium", "ssrf", "CWE-918")
    @property
    def sources(self): return [r'\$request->input\(.*url|.*\$request.*http']
    @property
    def sinks(self): return [r'Http::get\(.*\$|Http::post\(.*\$|curl_exec.*\$']
    @property
    def sanitizers(self): return [r'filter_var.*FILTER_VALIDATE_URL|parse_url.*host.*allow']
    def detect(self, content, file_path, taint_flow=None):
        if taint_flow and taint_flow.sink_category == "ssrf":
            return [FindingEvidence(self.meta.id, self.meta.severity, taint_flow.confidence, taint_flow.source, taint_flow.sink, file_path, taint_flow.sink_line, taint_flow.path,
                f"SSRF: {taint_flow.source} reaches Http::request", "Allow-list hosts, validate URL, block internal IPs", "ssrf",
                "User controls request URL → SSRF to internal services.")]
        return []

class MassAssignmentRule(SecurityRule):
    @property
    def meta(self): return RuleMeta("LARAVEL-MA-001", "Mass Assignment", "User input reaches Model::create/update without allow-list", "high", "mass_assignment", "CWE-915")
    @property
    def sources(self): return [r'\$request->all\(|->only\(.*\).*create']
    @property
    def sinks(self): return [r'::create\(.*\$request|->update\(.*\$request|->fill\(.*\$request']
    @property
    def sanitizers(self): return [r'->only\(.*\)', r'->validated\(\)-', r'->safe\(']
    def detect(self, content, file_path, taint_flow=None):
        if taint_flow and taint_flow.sink_category == "mass_assignment":
            return [FindingEvidence(self.meta.id, self.meta.severity, taint_flow.confidence, taint_flow.source, taint_flow.sink, file_path, taint_flow.sink_line, taint_flow.path,
                f"Mass assignment: {taint_flow.source} reaches {taint_flow.sink} in {file_path}:{taint_flow.sink_line}",
                "Use $request->validated() or ->only(['allowed']) + guarded fillable", "mass_assignment",
                "Attacker can set role, is_admin via mass assignment. Allow-list with only()/validated().")]
        return []

class AuthzRule(SecurityRule):
    @property
    def meta(self): return RuleMeta("LARAVEL-AUTHZ-001", "Authorization Bypass", "Sensitive operation without authorization check", "high", "authorization", "CWE-285")
    @property
    def sources(self): return [r'HTTP Request']
    @property
    def sinks(self): return [r'User::update|::delete|::create']
    @property
    def sanitizers(self): return [r'authorize\(\)|Gate::|Policy|can:|middleware.*auth']
    def detect(self, content, file_path, taint_flow=None):
        # This rule is handled via AuthorizationAnalyzer, not taint
        return []

class IdorRule(SecurityRule):
    @property
    def meta(self): return RuleMeta("LARAVEL-IDOR-001", "Insecure Direct Object Reference", "Model binding without ownership check", "high", "idor", "CWE-639")
    @property
    def sources(self): return [r'Patient\s+\$patient|User\s+\$user']
    @property
    def sinks(self): return [r'branch_id|patientQuery']
    @property
    def sanitizers(self): return [r'branchId\(\)|patientQuery\(\)|Gate::authorize']
    def detect(self, content, file_path, taint_flow=None):
        # Detect Patient $patient binding without branch check (from AF-02 IDOR)
        if re.search(r'function\s+\w+\s*\([^)]*Patient\s+\$patient', content):
            if "branch_id" not in content and "branchId" not in content and "patientQuery" not in content[max(0, content.find("Patient $patient")-2000): content.find("Patient $patient")+1500] if "Patient $patient" in content else True:
                # Need to check snippet around Patient binding, not whole file
                idx = content.find("Patient $patient")
                snippet = content[idx: idx+1500] if idx != -1 else ""
                if "branch_id" not in snippet and "branchId" not in snippet:
                    m = re.search(r'function\s+\w+\s*\([^)]*Patient\s+\$patient', content)
                    line = content[:m.start()].count("\n")+1 if m else 1
                    return [FindingEvidence(self.meta.id, self.meta.severity, "medium", "Patient $patient binding", "missing branch check", file_path, line, [file_path, "Patient binding", "update"],
                        f"IDOR: Patient model binding in {file_path}:{line} without branch_id check",
                        "Enforce $patient->branch_id === branchId() or use patientQuery()->findOrFail($id)", "idor",
                        f"Route model binding bypasses branch scoping. See AdminController.php:295 IDOR example.")]
        return []

# Registry
LARAVEL_RULES: List[SecurityRule] = [
    SqlInjectionRule(),
    XssRule(),
    CommandInjectionRule(),
    PathTraversalRule(),
    SsrfRule(),
    MassAssignmentRule(),
    AuthzRule(),
    IdorRule(),
]

@lru_cache(maxsize=32)
def get_rules(category: str | None = None) -> List[SecurityRule]:
    if category:
        return [r for r in LARAVEL_RULES if r.meta.category == category]
    return LARAVEL_RULES

# Project-specific rules loader (Plan #13)
def load_project_rules(project_root: pathlib.Path) -> List[SecurityRule]:
    """Load custom rules from rules/project/custom_rules.py if exists."""
    custom_path = project_root / "rules" / "project" / "custom_rules.py"
    if not custom_path.exists():
        custom_path = pathlib.Path("rules/project/custom_rules.py")
    if not custom_path.exists():
        return []
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("custom_rules", str(custom_path))
        if spec is None or spec.loader is None:
            return []
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        if hasattr(mod, "CUSTOM_RULES"):
            return mod.CUSTOM_RULES  # type: ignore
    except Exception as e:
        print(f"Warning: failed to load custom rules: {e}")
    return []
