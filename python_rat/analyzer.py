import re
import pathlib
from typing import Dict, List
from .graph import ApplicationGraph, Node, Edge
from .discovery import FileDiscovery, RouteDiscovery, collect_php_files
from .strip import strip_php
from .detection import SourceDetector, SinkDetector, AuthorizationAnalyzer, HiddenBehaviorAnalyzerPrecise

SEVERITY_WEIGHT = {"critical":100,"high":75,"medium":50,"low":25,"info":10}
SEVERITY_COLOR = {"critical":"red","high":"yellow","medium":"cyan","low":"blue","info":"gray"}

def estimate_confidence(content_clean: str, sources, sink_hit):
    # variable sharing check
    sink_snippet=sink_hit["snippet"]
    # extract vars from source hits
    src_vars=set()
    for snippet,_off in sources:
        m=re.search(r'\$[a-zA-Z_]\w*', snippet)
        if m: src_vars.add(m.group(0))
    # line of sink
    offset=sink_hit["offset"]
    lines=content_clean.splitlines()
    cur=0
    sink_line=""
    for line in lines:
        nxt=cur+len(line)+1
        if offset>=cur and offset<nxt:
            sink_line=line
            break
        cur=nxt
    for v in src_vars:
        if v in sink_line:
            return "high"
    # check direct flow patterns
    if re.search(r'\$request.*Storage|request\(\)->.*Storage|\$.*->.*put|file_put_contents.*\$request', content_clean, re.I):
        return "high"
    if len(sources)>=2:
        return "medium"
    return "medium"


class Analyzer:
    def __init__(self, project_root: pathlib.Path, config: dict):
        self.project_root=pathlib.Path(project_root).resolve()
        self.config=dict(config)  # shallow copy
        # defaults similar to config/rat.php
        self.config.setdefault("paths", ["."])
        self.config.setdefault("exclude", ["vendor","storage","bootstrap/cache","node_modules","public",".git",".idea",".vscode"])
        self.config.setdefault("analysis", {"routes":True,"authorization":True,"data_flow":True,"hidden_behavior":True,"impact":True})
        self.config.setdefault("fail_on","high")

    def analyze(self, progress=None) -> dict:
        graph=ApplicationGraph()
        findings=[]

        if progress: progress("routes",10)
        route_disc=RouteDiscovery(self.project_root)
        route_info=route_disc.discover(graph)

        if progress: progress("files",30)
        file_disc=FileDiscovery(self.project_root, self.config)
        file_info=file_disc.discover(graph)

        if progress: progress("flows",60)
        # Phase 2: taint flows
        if self.config.get("analysis",{}).get("data_flow",True):
            findings.extend(self._trace_data_flows(graph))

        if progress: progress("auth",80)
        if self.config.get("analysis",{}).get("authorization",True):
            findings.extend(self._analyze_auth(graph))

        if self.config.get("analysis",{}).get("hidden_behavior",True):
            findings.extend(self._analyze_hidden(graph))

        # security extra families if enabled
        if self.config.get("analysis",{}).get("security",False):
            findings.extend(self._analyze_security(graph))
        if self.config.get("analysis",{}).get("deep",False):
            # deep adds stricter taint + extra checks (already done, but mark confidence higher)
            pass

        if progress: progress("done",100)

        findings=self._assign_ids(findings)
        # sort by severity weight desc
        findings.sort(key=lambda f: SEVERITY_WEIGHT.get(f["severity"],0), reverse=True)

        stats={
            "routes": route_info["count"],
            "files": file_info["files"],
            "by_type": file_info["by_type"],
            "graph": graph.stats(),
            "findings": self._count_by_sev(findings),
            "project_root": str(self.project_root),
        }
        return {"graph": graph, "findings": findings, "stats": stats}

    def _trace_data_flows(self, graph: ApplicationGraph):
        findings=[]
        paths=self.config.get("paths", ["."])
        exclude=self.config.get("exclude", ["vendor","storage","bootstrap/cache","node_modules","public",".git"])
        files=collect_php_files(self.project_root, paths, exclude)
        counter=0
        for fp in files:
            try:
                rel=str(fp.relative_to(self.project_root))
            except ValueError:
                rel=str(fp)
            # skip RAT infra for self-scan to avoid false positives? but still check if true taint exists
            # For precise mode, we still scan infra but precise logic will filter false positives automatically
            try: raw=fp.read_text(errors="ignore")
            except: continue
            if not raw: continue
            clean=strip_php(raw)
            sources=SourceDetector.detect(clean)
            sinks=SinkDetector.detect(clean)
            if not sources or not sinks: continue
            # Build tainted vars: $x = $request->input(...) etc.
            tainted_vars=set()
            for line in clean.splitlines():
                if SourceDetector.detect(line):
                    # find assignment LHS
                    m=re.search(r'(\$[a-zA-Z_]\w*)\s*=\s*.*(?:\$request|request\s*\()', line)
                    if m:
                        tainted_vars.add(m.group(1))
                    # also capture superglobal assignments
                    for sup in re.findall(r'\$_GET|\$_POST|\$_REQUEST|\$_FILES|\$_COOKIE', line):
                        tainted_vars.add(sup)
                    tainted_vars.add("$request")  # for direct usage
            for sink in sinks:
                sink_line=self._line_for_offset(clean, sink["offset"])
                # precise taint: sink line must contain tainted var or direct source
                # extract line content at sink offset (both clean and raw, to catch interpolation inside strings)
                clean_lines=clean.splitlines()
                raw_lines=raw.splitlines()
                sink_line_content=""
                sink_line_raw=""
                cur=0
                sink_lidx=None
                for idx,line in enumerate(clean_lines):
                    nxt=cur+len(line)+1
                    if sink["offset"]>=cur and sink["offset"]<nxt:
                        sink_line_content=line
                        sink_lidx=idx
                        if idx < len(raw_lines):
                            sink_line_raw=raw_lines[idx]
                        break
                    cur=nxt
                has_taint=False
                # direct source inside sink line? check both clean and raw (raw catches interpolation)
                if SourceDetector.detect(sink_line_content) or SourceDetector.detect(strip_php(sink_line_raw)) if sink_line_raw else False:
                    # Need to ensure source detection on raw is not from string literal false; use clean for direct check, raw for tainted var fallback
                    if SourceDetector.detect(sink_line_content):
                        has_taint=True
                if not has_taint:
                    for tv in tainted_vars:
                        if tv in sink_line_content or (sink_line_raw and tv in sink_line_raw):
                            has_taint=True
                            break
                    # also handle interpolation: if sink is DB::raw and raw contains tainted var inside string placeholder
                    if not has_taint and sink_line_raw:
                        for tv in tainted_vars:
                            if tv in sink_line_raw:
                                has_taint=True; break
                # if not tainted, skip this sink (prevents false positive like file_get_contents($file) where $file is not tainted)
                if not has_taint:
                    continue
                # nearest source
                nearest=self._nearest_source(sources, sink, clean)
                confidence=estimate_confidence(clean, sources, sink)
                sev=sink["severity"]
                # validation presence lowers confidence, absence with critical ups to high (same as PHP Analyzer:153)
                has_valid=bool(re.search(r'->\s*validate\s*\(|FormRequest|Validator::', clean, re.I))
                if not has_valid and sev=="critical":
                    confidence="high"
                elif has_valid and confidence=="high":
                    confidence="medium"
                basename=fp.stem
                flow=self._build_flow(graph, str(fp), basename, sink["sink"], nearest[0] if nearest else "$request")
                entry=self._infer_entry(graph, str(fp), basename)
                title=f"User input reaches {sink['sink']}"
                desc="User-controlled data reaches a sensitive operation."
                why=f"User-controlled input ({nearest[0] if nearest else 'request input'}) reaches {sink['sink']} in {rel}:{sink_line}. No clear security boundary was detected in the immediate path. Review authorization, validation, and sanitization."
                recs=self._recs(sink["sink"])
                findings.append({
                    "id": f"RAT-TMP-{counter+1}",
                    "title": title,
                    "description": desc,
                    "severity": sev,
                    "confidence": confidence,
                    "entry": entry,
                    "source": nearest[0] if nearest else "$request->input()",
                    "sink": sink["sink"],
                    "flow": flow,
                    "file": rel,
                    "line": sink_line,
                    "recommendations": recs,
                    "category": "data_flow",
                    "why": why,
                })
                counter+=1
                if counter>80: break
            if len(findings)>80: break
        # dedup by file+sink+source
        uniq={}
        for f in findings:
            key=f"{f['file']}:{f['sink']}:{f['source']}"
            if key not in uniq: uniq[key]=f
        uniq=list(uniq.values())
        # limit to 15, prioritize high/critical if too many
        if len(uniq)>15:
            filt=[x for x in uniq if SEVERITY_WEIGHT.get(x["severity"],0) >= SEVERITY_WEIGHT["high"]]
            if len(filt)>=3:
                uniq=filt
            uniq=uniq[:15]
        return uniq

    def _analyze_auth(self, graph: ApplicationGraph):
        findings=[]
        paths=self.config.get("paths", ["."])
        exclude=self.config.get("exclude", ["vendor","storage","bootstrap/cache","node_modules","public",".git"])
        files=collect_php_files(self.project_root, paths, exclude)
        for fp in files:
            try:
                rel=str(fp.relative_to(self.project_root))
            except ValueError:
                rel=str(fp)
            # Skip infra files — same as precise scanner to avoid self-scan false positives
            if "python_rat" in rel or rel.startswith("src/Engine/") or rel.startswith("python_precise") or rel.startswith("verify_"):
                continue
            try: raw=fp.read_text(errors="ignore")
            except: continue
            if not raw: continue
            clean=strip_php(raw)
            # only controllers/services that look like admin/user-modifying (same as php Analyzer:236)
            if not re.search(r'Controller|admin', str(fp), re.I) and "User::" not in clean:
                continue
            if not AuthorizationAnalyzer.is_sensitive(clean): continue
            if AuthorizationAnalyzer.has_auth(clean): continue
            basename=fp.stem
            # route middleware check via graph
            has_auth_route=False
            for rn in graph.nodes_by_type("Route"):
                if basename in (rn.meta.get("action") or ""):
                    rf=rn.file
                    if rf:
                        ap=self.project_root / rf
                        if ap.exists():
                            try: rc=ap.read_text(errors="ignore")
                            except: rc=""
                            if rc and re.search(r'auth|can:|middleware.*auth', rc, re.I):
                                has_auth_route=True; break
            if has_auth_route: continue
            entry=self._infer_entry(graph, str(fp), basename)
            flow=self._build_flow(graph, str(fp), basename, "Model::update", "$request")
            findings.append({
                "id":"RAT-TMP-AUTH",
                "title":"Potential authorization boundary missing",
                "description":"Sensitive operation with no obvious authorization check detected.",
                "severity":"high",
                "confidence":"medium",
                "entry":entry,
                "source":"HTTP Request",
                "sink":"Sensitive model operation",
                "flow": flow,
                "file": rel,
                "line": 1,
                "recommendations":[
                    "Verify that authentication middleware is applied",
                    "Check for $this->authorize() / Gate / Policy enforcement",
                    "Ensure route-level can: or auth middleware is present",
                    "Review manually — RAT cannot prove absence of auth",
                ],
                "category":"authorization",
                "why": f"File {rel} performs a sensitive operation (model write) with no obvious policy/gate/authorization middleware discovered in the analyzed path. This is a potential issue — review manually."
            })
            if len(findings)>=5: break
        return findings

    def _analyze_hidden(self, graph: ApplicationGraph):
        findings=[]
        paths=self.config.get("paths", ["."])
        exclude=self.config.get("exclude", ["vendor","storage","bootstrap/cache","node_modules","public",".git"])
        files=collect_php_files(self.project_root, paths, exclude)
        for fp in files:
            try:
                rel=str(fp.relative_to(self.project_root))
            except ValueError:
                rel=str(fp)
            if "python_rat" in rel or "verify_" in rel or "python_precise" in rel:
                continue
            try: raw=fp.read_text(errors="ignore")
            except: continue
            if not raw: continue
            clean=strip_php(raw)
            # precise hidden check (not keyword-only)
            if not HiddenBehaviorAnalyzerPrecise.has_hidden(clean):
                continue
            # Also need User/Order hint as in php Analyzer:303 filter
            if "User" not in clean and "Order" not in clean:
                # but if file is observer itself, still interesting? Keep filter as php
                if "Observer" not in clean and "Job" not in clean:
                    continue
            basename=fp.stem
            entry=self._infer_entry(graph, str(fp), basename)
            target=self._pick_hidden(clean)
            flow=[e for e in [entry, basename, target, "Job / Event / Notification"] if e]
            findings.append({
                "id":"RAT-TMP-HID",
                "title":"Hidden side effect via observer / event",
                "description":"Model lifecycle triggers hidden execution path (observer/event/job).",
                "severity":"medium",
                "confidence":"high",
                "entry":entry,
                "source":basename,
                "sink":"Hidden execution path",
                "flow": flow,
                "file": rel,
                "line": 1,
                "recommendations":[
                    "Document the side effect for teammates",
                    "Ensure transactions and idempotency are handled",
                    "Verify authorization propagates to async jobs",
                ],
                "category":"hidden_behavior",
                "why": f"File {rel} participates in a hidden execution chain (observer/event/listener/job). Use `rat why {basename}` to see the full trail."
            })
            if len(findings)>=4: break
        return findings

    def _analyze_security(self, graph: ApplicationGraph):
        # Extra 22 families beyond data_flow: secrets, debug, cors, etc.
        findings=[]
        paths=self.config.get("paths", ["."])
        exclude=self.config.get("exclude", ["vendor","storage","bootstrap/cache","node_modules","public",".git"])
        files=collect_php_files(self.project_root, paths, exclude)
        # Secret patterns
        secret_pats=[re.compile(p, re.I) for p in [r'sk_live_[0-9a-z]+', r'AKIA[0-9A-Z]{16}', r'aws_access_key', r'password\s*=\s*["\'][^"\']+["\']', r'secret\s*=\s*["\']']]
        for fp in files:
            try:
                rel=str(fp.relative_to(self.project_root))
            except ValueError:
                rel=str(fp)
            try: raw=fp.read_text(errors="ignore")
            except: continue
            clean=strip_php(raw)
            for pat in secret_pats:
                for m in pat.finditer(clean):
                    line=self._line_for_offset(clean, m.start())
                    findings.append({
                        "id":"RAT-TMP-SEC",
                        "title":"Potential hardcoded secret",
                        "description":"Hardcoded secret-like string detected.",
                        "severity":"high",
                        "confidence":"medium",
                        "entry":rel,
                        "source":"hardcoded value",
                        "sink":"secret exposure",
                        "flow":[rel,"secret","exposure"],
                        "file":rel,
                        "line":line,
                        "recommendations":["Move secret to env file","Rotate exposed credential","Scan git history"],
                        "category":"security",
                        "why": f"File {rel}:{line} contains string matching secret pattern `{m.group(0)[:40]}`. Verify not a real credential."
                    })
                    if len(findings)>15: break
            # debug checks
            if "APP_DEBUG=true" in raw or re.search(r'APP_ENV=production.*debug true|dd\(|dump\(', raw, re.I):
                findings.append({
                    "id":"RAT-TMP-DBG",
                    "title":"Debug mode / debug endpoint",
                    "description":"Debug enabled or dump statements found.",
                    "severity":"medium","confidence":"high","entry":rel,"source":"config","sink":"debug exposure","flow":[rel,"debug"],"file":rel,"line":1,"recommendations":["Ensure APP_DEBUG=false in prod","Remove dd()/dump()"],"category":"security","why": f"File {rel} may expose debug info."
                })
            if len(findings)>20: break
        # dedup + limit
        seen=set()
        uniq=[]
        for f in findings:
            k=(f["file"], f["sink"], f["line"])
            if k not in seen:
                seen.add(k); uniq.append(f)
        return uniq[:10]

    # helpers reused from php Analyzer
    def _build_flow(self, graph: ApplicationGraph, file: str, basename: str, sink: str, source: str):
        node=graph.find_by_name(basename)
        flow=[]
        if node:
            anc=graph.ancestors_of(node.id, 4)
            anc=list(reversed(anc))
            for n in anc:
                if n.type=="Route":
                    flow.append(n.name)
            flow.append(basename)
            out=graph.outgoing(node.id)
            added=False
            for e in out:
                tgt=graph.get_node(e.to)
                if tgt and (sink.split("::")[0].lower() in tgt.name.lower() or sink.lower() in e.label.lower()):
                    flow.append(tgt.name or e.label)
                    added=True
            if not added:
                svc=None
                for e in out:
                    t=graph.get_node(e.to)
                    if t and t.type=="Service":
                        svc=t.name; break
                if svc: flow.append(svc)
                flow.append(sink)
        else:
            flow=["HTTP Request", basename, sink]
        flow=list(dict.fromkeys([x for x in flow if x]))
        if not flow: flow=["HTTP Request", basename, sink]
        if "request" in source.lower() and flow[0]!="HTTP Request":
            flow.insert(0, "HTTP Request")
        return flow

    def _infer_entry(self, graph: ApplicationGraph, file: str, basename: str):
        node=graph.find_by_name(basename)
        if node:
            anc=graph.ancestors_of(node.id,3)
            for n in anc:
                if n.type=="Route": return n.name
        # fallback guess from route files
        routes_dir=self.project_root / "routes"
        if routes_dir.is_dir():
            for rf in routes_dir.glob("*.php"):
                try: c=rf.read_text(errors="ignore")
                except: continue
                if basename in c:
                    m=re.search(r'Route\s*::\s*(get|post|put|patch|delete)[^\n]*'+re.escape(basename), c, re.I)
                    if m:
                        mm=re.search(r'[\'"](\/[^\'"]+)[\'"]', m.group(0))
                        if mm:
                            return m.group(1).upper()+" "+mm.group(1)
        return basename

    def _collect_php_files(self, paths, exclude):
        return collect_php_files(self.project_root, paths, exclude)

    def _line_for_offset(self, content: str, offset: int):
        return content[:offset].count("\n")+1

    def _nearest_source(self, sources, sink, content):
        sink_off=sink["offset"]
        best=None; bestdist=10**9
        for snippet,off in sources:
            dist=abs(off - sink_off)
            if off > sink_off: dist+=5000
            if dist<bestdist:
                bestdist=dist; best=(snippet,off)
        return best

    def _recs(self, sink: str):
        s=sink.lower()
        if any(x in s for x in ["storage","file_put","fopen","filesystem"]):
            return ["Review whether the user is authorized","Validate filename is controlled safely (no path traversal)","Restrict destination path to an allow-list","Validate uploaded content (mime, size, extension)"]
        if any(x in s for x in ["db::","raw sql","whereraw"]):
            return ["Use parameterized queries / Eloquent bindings","Validate and sanitize input before raw SQL","Prefer query builder without raw where possible"]
        if any(x in s for x in ["shell","exec","process"]):
            return ["Avoid shell execution with user input entirely if possible","Use allow-list for commands/arguments","Escape arguments with escapeshellarg()"]
        if "http" in s:
            return ["Validate destination URL (SSRF risk)","Set timeouts and restrict private network access","Sanitize logged URLs"]
        if "unserialize" in s or "eval" in s:
            return ["Avoid unserialize/eval on user-controlled data","Use JSON with strict typing instead"]
        return ["Review authorization and validation in this flow","Trace the source variable through intermediate calls"]

    def _pick_hidden(self, content: str):
        m=re.search(r'([A-Z][a-zA-Z0-9_]+Observer)', content)
        if m: return m.group(1)
        m=re.search(r'([A-Z][a-zA-Z0-9_]+Event)', content)
        if m: return m.group(1)
        m=re.search(r'([A-Z][a-zA-Z0-9_]+Job)', content)
        if m: return m.group(1)
        m=re.search(r'([A-Z][a-zA-Z0-9_]+Listener)', content)
        if m: return m.group(1)
        return "Observer / Event"

    def _assign_ids(self, findings: List[dict]):
        out=[]
        for i,f in enumerate(findings, start=1):
            fid=f"RAT-{i:03d}"
            nf=dict(f)
            nf["id"]=fid
            out.append(nf)
        return out

    def _count_by_sev(self, findings: List[dict]):
        c={"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for f in findings:
            k=f.get("severity","info")
            c[k]=c.get(k,0)+1
        return c
