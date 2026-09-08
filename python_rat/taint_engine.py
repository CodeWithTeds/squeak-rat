"""
taint_engine.py — Interprocedural Taint Engine (Plan #2, #4, #6)
Tracks user-controlled data from sources through assignments, arrays, function calls,
services, repositories until sinks. Builds data-flow path with evidence.

Core question per Plan: "Where did data originate? How did it travel? Was it validated/sanitized? Where did it end up? Can that path create vulnerability?"
"""
from __future__ import annotations
import re
import pathlib
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from functools import lru_cache
from .strip import strip_php
from .knowledge_base import get_kb
from .project_index import ProjectIndex

@dataclass
class TaintFlow:
    source: str
    source_file: str
    source_line: int
    sink: str
    sink_file: str
    sink_line: int
    sink_category: str
    severity: str
    confidence: str
    path: List[str]  # e.g. ["HTTP Request", "UserController::search", "UserService::find", "DB::raw"]
    evidence: List[str]  # code snippets per step
    sanitized: bool = False
    sanitizers: List[str] = field(default_factory=list)
    validation_rules: Optional[str] = None

@dataclass
class VariableState:
    """Tracks taint per variable within a file/scope."""
    tainted: Set[str] = field(default_factory=set)
    sanitized: Set[str] = field(default_factory=set)
    assignments: Dict[str, Tuple[str, int]] = field(default_factory=dict)  # var -> (rhs, line)

class TaintEngine:
    """
    Interprocedural taint analysis.
    Follows HTTP Request -> Controller -> Service -> Repository -> DB/File/External
    Uses knowledge base for sources/sinks/sanitizers.
    """

    def __init__(self, project_root: pathlib.Path, project_index: Optional[ProjectIndex] = None):
        self.project_root = pathlib.Path(project_root).resolve()
        self.kb = get_kb()
        self.index = project_index
        # Cache for file variable states (incremental)
        self._file_states: Dict[str, VariableState] = {}

    @lru_cache(maxsize=1024)
    def _strip(self, content: str) -> str:
        return strip_php(content)

    def analyze_file(self, file_path: pathlib.Path) -> List[TaintFlow]:
        """Intraprocedural analysis for single file → flows with taint."""
        try:
            rel = str(file_path.relative_to(self.project_root))
        except ValueError:
            rel = str(file_path)
        try:
            raw = file_path.read_text(errors="ignore")
        except:
            return []
        if not raw:
            return []
        clean = self._strip(raw)
        # Quick filter: need both source and sink in clean? but sinks via KB may be broader
        # Use KB detection
        sources = self.kb.detect_sources(clean)
        # Use sink detection on clean + also check raw for Blade etc
        sinks = self.kb.detect_sinks(clean)
        # Also check Storage etc via raw for file_sink variants
        if not sources or not sinks:
            return []

        # Build variable-level taint (Plan #2)
        state = self._build_variable_state(clean, raw)
        self._file_states[rel] = state

        flows: List[TaintFlow] = []
        clean_lines = clean.splitlines()
        raw_lines = raw.splitlines()

        for sink in sinks:
            offset = sink["offset"]
            # Find line for sink
            cur = 0
            sink_line_idx = None
            sink_line_content = ""
            sink_line_raw = ""
            sink_line_num = 1
            for idx, line in enumerate(clean_lines):
                nxt = cur + len(line) + 1
                if offset >= cur and offset < nxt:
                    sink_line_idx = idx
                    sink_line_content = line
                    if idx < len(raw_lines):
                        sink_line_raw = raw_lines[idx]
                    sink_line_num = idx + 1
                    break
                cur = nxt
            if sink_line_idx is None:
                continue

            # Determine if tainted var reaches sink
            has_taint, tainted_vars_used, evidence = self._is_tainted_at_sink(
                sink, sink_line_content, sink_line_raw, clean, raw, state
            )
            if not has_taint:
                continue

            # Check sanitization/validation awareness (Plan #7)
            sanitized, sanitizers = self._check_sanitization(sink, sink_line_content, sink_line_raw, clean, raw, tainted_vars_used)
            # Validation analysis: find validation rules for this variable
            validation_rules = self._extract_validation_rules(clean, raw, tainted_vars_used)
            is_validation_sufficient = False
            if validation_rules and sanitized:
                # For injection, validation alone insufficient if not parameterized
                is_validation_sufficient = self.kb.is_validation_sufficient(validation_rules, sink["category"])
            # Re-evaluate taint if sanitized properly for this sink category (Plan #7)
            if sanitized:
                if sink["category"] == "mass_assignment" and any(s in sanitizers for s in ["only", "validated", "safe"]):
                    continue
                if sink["category"] == "xss" and any(s in sanitizers for s in ["e()", "escape", "blade", "htmlspecialchars"]):
                    if "e(" in sink_line_content or "{{" in sink_line_raw or "htmlspecialchars" in sink_line_content:
                        continue
                if sink["category"] == "injection" and "parameterized" in sanitizers:
                    continue
                if sink["category"] == "path_traversal" and any(s in sanitizers for s in ["basename", "store", "hashName"]):
                    continue
                if sink["category"] == "ssrf" and any(s in sanitizers for s in ["allowlist", "filter_var", "parse_url"]):
                    # SSRF allow-list check: if file contains in_array with allowed hosts before Http::get, consider sanitized
                    if re.search(r'in_array\s*\(.*\$host.*allowed|parse_url.*host', clean, re.I):
                        continue
                # Generic: if sanitized for this category and validation sufficient, skip
                if sink["category"] in ("injection", "xss", "path_traversal") and is_validation_sufficient:
                    # But for injection, validation alone not sufficient without parameterization, already handled
                    pass

            # Mass assignment precise filtering (extend window)
            if sink["id"] == "mass_assignment":
                extended_raw = raw[sink["offset"]: sink["offset"]+1500] if "mass_assignment" in sink["id"] else ""
                combined = (sink_line_content or "") + " " + (sink_line_raw or "") + " " + extended_raw
                if "$request->only(" in combined or "$request->validated(" in combined or "$request->safe(" in combined:
                    continue
                if "=>" in combined and "$request->all()" not in combined:
                    # explicit allow-list -> not mass assignment
                    # Check if sensitive keys present from tainted var?
                    lower = combined.lower()
                    has_sensitive = any(k in lower for k in ["is_admin", "is_super", "role", "branch_id"])
                    if not has_sensitive:
                        continue
                    # If sensitive but not tainted var in same assignment, skip
                    tainted_in_extended = any(tv in extended_raw for tv in tainted_vars_used)
                    if not tainted_in_extended and not re.search(r'is_admin.*\$request|branch_id.*\$request', lower, re.I):
                        continue

            # Nearest source
            nearest = self._nearest_source(sources, sink, clean)
            # Build interprocedural path if index available
            path = self._build_interprocedural_path(rel, sink, nearest)
            confidence = self._estimate_confidence(sources, sink, has_taint, sanitized, sink["severity"], clean)

            flows.append(TaintFlow(
                source=nearest["snippet"] if nearest else "$request->input()",
                source_file=rel,
                source_line=nearest_line(clean, nearest["offset"]) if nearest else sink_line_num,
                sink=sink["sink_name"],
                sink_file=rel,
                sink_line=sink_line_num,
                sink_category=sink["category"],
                severity=sink["severity"],
                confidence=confidence,
                path=path,
                evidence=evidence or [sink_line_content.strip()[:160] or sink_line_raw.strip()[:160]],
                sanitized=sanitized,
                sanitizers=sanitizers,
                validation_rules=validation_rules,
            ))
        return flows

    def _build_variable_state(self, clean: str, raw: str) -> VariableState:
        state = VariableState()
        # Detect FormRequest: class XRequest extends FormRequest
        has_formrequest = bool(re.search(r'class\s+\w+Request\b', raw))
        for line in clean.splitlines():
            # Source assignments: $x = $request->input(...)
            if self.kb.is_source_line(line):
                m = re.search(r'(\$[a-zA-Z_]\w*)\s*=\s*.*(?:\$request|request\s*\()', line)
                if m:
                    var = m.group(1)
                    if re.search(r'->\s*(validate|validated|safe|only)\s*\(', line):
                        state.sanitized.add(var)
                        state.assignments[var] = (line, 1)
                    else:
                        state.tainted.add(var)
                        state.assignments[var] = (line, 1)
                for sup in re.findall(r'\$_GET|\$_POST|\$_REQUEST|\$_FILES|\$_COOKIE|\$_SERVER', line):
                    state.tainted.add(sup)
                state.tainted.add("$request")
            # Sanitizer assignments: $data = $request->validated() etc
            m2 = re.search(r'(\$[a-zA-Z_]\w*)\s*=\s*\$request->\s*(safe|validated)\b', line)
            if m2:
                state.sanitized.add(m2.group(1))
            m3 = re.search(r'(\$[a-zA-Z_]\w*)\s*=\s*\$request->\s*validate\s*\(', line)
            if m3:
                state.sanitized.add(m3.group(1))
            m4 = re.search(r'(\$[a-zA-Z_]\w*)\s*=\s*\$request->\s*only\s*\(', line)
            if m4:
                state.sanitized.add(m4.group(1))
            # Propagation: $y = $x where $x tainted -> $y tainted (simple)
            # This enables interprocedural via variable chain within file
            m_prop = re.search(r'(\$[a-zA-Z_]\w*)\s*=\s*(\$[a-zA-Z_]\w*)', line)
            if m_prop:
                lhs, rhs = m_prop.groups()
                if rhs in state.tainted and lhs not in state.sanitized:
                    state.tainted.add(lhs)
                if rhs in state.sanitized:
                    state.sanitized.add(lhs)
            # Array propagation: $arr['key'] = $request->input()
            if re.search(r'\$[a-zA-Z_]\w*\s*\[.*\]\s*=\s*.*\$request', line):
                m_arr = re.search(r'(\$[a-zA-Z_]\w*)', line)
                if m_arr:
                    state.tainted.add(m_arr.group(1))
        return state

    def _is_tainted_at_sink(self, sink: Dict, sink_line_clean: str, sink_line_raw: str, clean: str, raw: str, state: VariableState) -> Tuple[bool, List[str], List[str]]:
        """Check if tainted var reaches sink argument (variable-level taint)."""
        # Dynamic function call special: function name must be tainted
        if sink["id"] == "dynamic_function":
            m = re.search(r'\$([a-zA-Z_]\w*)\s*\(\s*\$', sink_line_clean)
            if m:
                func_var = "$" + m.group(1)
                if func_var in state.tainted:
                    return True, [func_var], [sink_line_clean.strip()]
            return False, [], []
        if sink["id"] == "dynamic_instantiation":
            m = re.search(r'new\s+(\$[a-zA-Z_]\w*)', sink_line_clean)
            if m and m.group(1) in state.tainted:
                return True, [m.group(1)], [sink_line_clean.strip()]
            return False, [], []

        # Direct source in same line? (e.g., Storage::put($request->input(...)))
        if self.kb.is_source_line(sink_line_clean) or self.kb.is_source_line(self._strip(sink_line_raw) if sink_line_raw else ""):
            return True, ["$request"], [sink_line_clean.strip() or sink_line_raw.strip()]

        # Check tainted vars in line
        found = []
        evidence = []
        for tv in state.tainted:
            if tv in sink_line_clean or (sink_line_raw and tv in sink_line_raw):
                found.append(tv)
                evidence.append(sink_line_clean.strip() or sink_line_raw.strip())
        # Also check for superglobal directly in sink line
        for sup in ["$_GET", "$_POST", "$_REQUEST", "$_FILES", "$_COOKIE"]:
            if sup in sink_line_clean:
                found.append(sup)
        if found:
            return True, found, evidence

        # For mass assignment, check extended window
        if sink["id"] == "mass_assignment":
            extended = raw[sink["offset"]: sink["offset"]+1500] if sink["offset"] < len(raw) else ""
            for tv in state.tainted:
                if tv in extended:
                    return True, [tv], [sink_line_clean.strip() + " ... (extended)"]
            if self.kb.is_source_line(self._strip(extended)):
                return True, ["$request"], [extended.strip()[:120]]

        return False, [], []

    def _check_sanitization(self, sink: Dict, sink_line: str, sink_line_raw: str, clean: str, raw: str, tainted_vars: List[str]) -> Tuple[bool, List[str]]:
        sanitizers: List[str] = []
        # Check line-level sanitizers
        for s_def, pat in self.kb._sanitizer_res:
            if pat.search(sink_line):
                sanitizers.append(s_def.id)
        # Also check raw line for sanitizers that are inside string literals
        if sink_line_raw:
            for s_def, pat in self.kb._sanitizer_res:
                if pat.search(sink_line_raw) and s_def.id not in sanitizers:
                    sanitizers.append(s_def.id)
        # For injection, parameterized query is sanitization regardless of validation
        # Need to check both clean and raw because ? is inside string literal which becomes __STR in clean
        raw_for_check = sink_line_raw or sink_line
        if sink["category"] == "injection":
            # Use strict pattern: ? placeholder or :named binding not preceded by : (avoid ::)
            if re.search(r'\?\s*[,\)\]]|(?<!:):(?!:)[\w]+\b', sink_line) or re.search(r'\?\s*[,\)\]]', raw_for_check):
                if "parameterized" not in sanitizers:
                    sanitizers.append("parameterized")
            # Also check if sink line is Eloquent where() with 2 args (where('col', $var)) is parameterized
            if re.search(r'->\s*where\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*\$', sink_line) or re.search(r'->\s*where\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*\$', raw_for_check):
                if "parameterized" not in sanitizers:
                    sanitizers.append("parameterized")
            # Check raw for ? inside string literal (e.g., 'SELECT ... ?')
            if "?" in raw_for_check and "DB::" in raw_for_check:
                if "parameterized" not in sanitizers:
                    # Only if ? is inside DB::select/raw and tainted var is passed as separate param
                    if re.search(r'\?\s*[\'"]\s*,\s*\[.*\$', raw_for_check) or re.search(r'\?\s*[\'"]\s*,\s*\$', raw_for_check):
                        sanitizers.append("parameterized")
        # SSRF allow-list: check whole file for allow-list pattern (Plan #7)
        if sink["category"] == "ssrf":
            if re.search(r'in_array\s*\(.*\$host.*allowed|parse_url\s*\(.*host|filter_var\s*\(.*FILTER_VALIDATE_URL', clean, re.I):
                if "allowlist" not in sanitizers:
                    sanitizers.append("allowlist")
            if re.search(r'parse_url.*host', clean, re.I) and "allowed" in clean.lower():
                if "allowlist" not in sanitizers:
                    sanitizers.append("allowlist")
        # Path traversal basename/store
        if sink["category"] == "path_traversal":
            if re.search(r'basename\s*\(|->\s*store\s*\(|hashName', sink_line):
                if "basename" not in sanitizers:
                    sanitizers.append("basename")
        # E for xss — use strict word boundary to avoid false e( in whereRaw etc
        if re.search(r'\be\s*\(\s*.*\$', sink_line) or "htmlspecialchars" in sink_line:
            if "e()" not in sanitizers:
                sanitizers.append("e()")
        # Add parameterized for any injection line with ? regardless of validation
        has_valid = bool(re.search(r'->\s*validate\s*\(|FormRequest', clean, re.I))
        is_sanitized = bool(sanitizers) and self.kb.is_sanitized(sink_line, sink["category"])
        # For SSRF allowlist, file-level check counts as sanitized even if line doesn't contain pattern
        if "allowlist" in sanitizers and sink["category"] == "ssrf":
            return True, sanitizers
        # For injection parameterized, line-level is sufficient even if KB pattern not matched exactly due to regex strictness
        if "parameterized" in sanitizers and sink["category"] == "injection":
            return True, sanitizers
        # Even if sanitizers found, need to verify they actually apply to sink category per KB
        if sanitizers:
            for s in sanitizers:
                # Find sanitizer definition mitigates
                for sd, _ in self.kb._sanitizer_res:
                    if sd.id == s and sink["category"] in sd.mitigates:
                        return True, sanitizers
        # If sanitizers found but not for this category, not considered sanitized
        return False, sanitizers

    def _extract_validation_rules(self, clean: str, raw: str, tainted_vars: List[str]) -> Optional[str]:
        # Extract validation rules from file: 'field' => 'required|string|max:255' or Rule::enum
        rules = []
        for m in re.finditer(r'[\'"]([^\'"]+)[\'"]\s*=>\s*[\'"]([^\'"]+)[\'"]', raw):
            rules.append(m.group(2))
        for m in re.finditer(r'Rule::enum\s*\(\s*([^\)]+)\)', raw):
            rules.append(f"enum:{m.group(1)}")
        if rules:
            return "|".join(rules[:5])
        # Also detect FormRequest rules method
        if "function rules" in raw:
            chunk = raw[raw.find("function rules"): raw.find("function rules")+1000] if "function rules" in raw else ""
            if chunk:
                return chunk[:200]
        return None

    def _nearest_source(self, sources: List[Dict], sink: Dict, clean: str) -> Optional[Dict]:
        # Find source with offset closest before sink
        best = None
        best_dist = float('inf')
        for src in sources:
            if src["offset"] < sink["offset"]:
                dist = sink["offset"] - src["offset"]
                if dist < best_dist:
                    best_dist = dist
                    best = src
        return best or (sources[0] if sources else None)

    def _build_interprocedural_path(self, file_rel: str, sink: Dict, nearest: Optional[Dict]) -> List[str]:
        """Build data-flow path: HTTP Request -> Controller -> Service -> Repository -> Sink"""
        path = ["HTTP Request"]
        # Try to infer from index
        basename = pathlib.Path(file_rel).stem
        if self.index:
            # Find file's class in index
            cls = self.index.file_to_class.get(file_rel, basename)
            # Walk ancestors via graph
            try:
                from .graph import ApplicationGraph
                # Use index graph if built
                # For now simple: controller->service->sink
                path.append(basename)
                # Add intermediate if file contains Service/Repository reference
                # Extract service names from file_rel? We can add generic
                if "Controller" in basename and sink["id"] not in ("mass_assignment",):
                    # Try to find service mentioned in file
                    # This would be better with AST
                    path.append(sink["sink_name"])
                else:
                    path.append(sink["sink_name"])
            except:
                path.append(basename)
                path.append(sink["sink_name"])
        else:
            path.append(basename)
            path.append(sink["sink_name"])
        # Deduplicate
        dedup = []
        for p in path:
            if not dedup or dedup[-1] != p:
                dedup.append(p)
        return dedup

    def _estimate_confidence(self, sources: List[Dict], sink: Dict, has_taint: bool, sanitized: bool, severity: str, clean: str) -> str:
        if not has_taint:
            return "low"
        if sanitized:
            return "low"
        # Check variable sharing strength
        if len(sources) >= 2 and sink["severity"] == "critical":
            return "high"
        has_validation = bool(re.search(r'->\s*validate|FormRequest|Validator::', clean, re.I))
        if not has_validation and severity == "critical":
            return "high"
        if has_validation and severity == "critical":
            return "medium"
        if has_taint and sink["severity"] in ("critical", "high"):
            return "high"
        return "medium"

def nearest_line(clean: str, offset: int) -> int:
    return clean[:offset].count("\n") + 1

# ── Interprocedural wrapper: follow taint across files ──
class InterproceduralTaintEngine:
    """
    Extends TaintEngine to follow data across function boundaries (Plan #4).
    Example: Controller -> Service -> Repository -> DB
    """
    def __init__(self, project_root: pathlib.Path, index: ProjectIndex):
        self.project_root = project_root
        self.index = index
        self.engine = TaintEngine(project_root, index)

    def analyze_project(self, php_files: List[pathlib.Path]) -> List[TaintFlow]:
        """ Analyze entire project with cross-file taint."""
        # First phase: intraprocedural per file
        flows: List[TaintFlow] = []
        for fp in php_files:
            flows.extend(self.engine.analyze_file(fp))
        # Second phase: interprocedural correlation (simple: if controller taints service, and service taints DB, link)
        # Build map from class -> tainted params
        # For now, augment path evidence: if flow in service, try to link to controller that calls service
        augmented = self._correlate_flows(flows)
        return augmented

    def _correlate_flows(self, flows: List[TaintFlow]) -> List[TaintFlow]:
        """Correlate flows across files via call graph."""
        # Group by sink category
        by_file = {}
        for f in flows:
            by_file.setdefault(f.sink_file, []).append(f)
        # If a controller has taint and calls a service that also has taint, extend path
        for flow in flows:
            # Try to prepend caller
            basename = pathlib.Path(flow.sink_file).stem
            # Look for callers in index graph
            if self.index:
                for cls_name, ci in self.index.classes.items():
                    if ci.type == "Controller" and basename != cls_name:
                        # Does controller file mention this sink_file's class?
                        controller_file = self.index.class_to_file.get(cls_name)
                        if not controller_file:
                            continue
                        try:
                            content = (self.project_root / controller_file).read_text(errors="ignore")
                            if basename in content or flow.sink in content:
                                # Extend path: Controller is upstream
                                if cls_name not in flow.path:
                                    flow.path = ["HTTP Request", cls_name] + flow.path[1:]
                        except:
                            pass
        return flows
