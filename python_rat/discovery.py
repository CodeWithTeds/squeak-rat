import re
import pathlib
from typing import List, Dict
from .graph import ApplicationGraph, Node, Edge
from .strip import strip_php

# Same heuristics as PHP FileDiscovery.php:108
def infer_type(file_path: str, content: str, basename: str) -> str:
    lower=file_path.lower()
    clower=content.lower()
    if "/http/controllers" in lower or basename.endswith("Controller"):
        return "Controller"
    if "/models" in lower or "/entities" in lower or "/aggregates" in lower or ("/domain" in lower and ("/entity" in lower or "/aggregate" in lower or "extends Model" in content)):
        return "Model"
    if "extends Model" in content or basename.endswith("Model"):
        return "Model"
    if "/services" in lower or "/application/services" in lower or ("/domain/" in lower and "/service" in lower) or basename.endswith("Service"):
        return "Service"
    if "/jobs" in lower or "shouldqueue" in clower or basename.endswith("Job"):
        return "Job"
    if "/events" in lower or basename.endswith("Event"):
        return "Event"
    if "/listeners" in lower or basename.endswith("Listener"):
        return "Listener"
    if "/observers" in lower or basename.endswith("Observer"):
        return "Observer"
    if "/middleware" in lower or basename.endswith("Middleware"):
        return "Middleware"
    if "/notifications" in lower or basename.endswith("Notification"):
        return "Notification"
    if "/mail" in lower or basename.endswith("Mail"):
        return "Mail"
    if "/actions" in lower or "/handlers" in lower or "/usecases" in lower or "/use_cases" in lower or basename.endswith("Action") or basename.endswith("Handler") or basename.endswith("UseCase"):
        return "Service"
    if basename.endswith("Repository") or basename.endswith("Manager") or basename.endswith("Provider"):
        return "Service"
    if "/livewire" in lower or "/components" in lower:
        return "Controller"
    if "class" in content and "Controller" in content:
        return "Controller"
    return "Other"

LARAVEL_LOT = ["app","routes","config","database","resources","Modules","modules","Domain","domain","Domains","src","packages","services","Services","apps","microservices","tests"]

def collect_php_files(project_root: pathlib.Path, paths: List[str], exclude: List[str]) -> List[pathlib.Path]:
    files=[]
    for p in paths:
        if p==".":
            full=project_root
        else:
            pp=pathlib.Path(p)
            if pp.is_absolute():
                full=pp
            else:
                full = project_root / p.lstrip("/")
        if full.is_file() and full.suffix==".php":
            files.append(full)
            continue
        if not full.is_dir():
            # try glob-ish for entries like "app" when root is "."? Already handled as dir
            continue
        for fp in full.rglob("*.php"):
            try:
                rel = str(fp.relative_to(project_root))
            except ValueError:
                # fp outside project_root (absolute path) -> use absolute or relative to scanned root
                try:
                    rel = str(fp.relative_to(full if full.is_dir() else full.parent))
                except:
                    rel = str(fp)
            skip=False
            for ex in exclude:
                ex=ex.strip("/")
                if rel==ex or rel.startswith(ex+"/") or f"/{ex}/" in rel or rel.startswith(ex):
                    skip=True; break
                # also handle bootstrap/cache case
                if ex in rel.split("/"):
                    # check exact segment
                    if ex in rel.split("/"):
                        # already handled
                        pass
            if skip:
                continue
            # need more robust exclude check (same as php)
            for ex in exclude:
                if rel.startswith(ex) or f"/{ex}/" in f"/{rel}/":
                    skip=True; break
            if skip: continue
            files.append(fp)
    # dedup
    uniq={}
    for f in files:
        uniq[str(f.resolve())]=f
    return sorted(uniq.values(), key=lambda p: str(p))

class FileDiscovery:
    def __init__(self, project_root: pathlib.Path, config: dict):
        self.project_root=project_root
        self.config=config

    def discover(self, graph: ApplicationGraph) -> dict:
        paths=self.config.get("paths", ["."])
        exclude=self.config.get("exclude", ["vendor","storage","bootstrap/cache","node_modules","public",".git",".idea",".vscode"])
        all_files=collect_php_files(self.project_root, paths, exclude)
        by_type={}
        for fp in all_files:
            try:
                rel=str(fp.relative_to(self.project_root))
            except ValueError:
                rel=str(fp)
            try:
                content=fp.read_text(errors="ignore")
            except: content=""
            basename=fp.stem
            typ=infer_type(str(fp), content, basename)
            by_type[typ]=by_type.get(typ,0)+1
            nid=f"{typ.lower()}:{basename}"
            # ensure unique per typ:basename, but models etc same basename allowed different prefix
            if not graph.has_node(nid):
                graph.add_node(Node(id=nid, type=typ, name=basename, file=rel, line=1))
            self._infer_edges(graph, nid, content)
            # hidden behavior meta deferred to Analyzer (precise check)
        return {"files": len(all_files), "by_type": by_type}

    def _infer_edges(self, graph: ApplicationGraph, from_id: str, content: str):
        clean=strip_php(content)
        # Class usages: Foo::  (but exclude facades we map to external types)
        for m in re.finditer(r'\b([A-Z][a-zA-Z0-9_]+)\s*::', clean):
            cls=m.group(1)
            if cls in ["DB","Schema","Cache","Storage","Http","Auth","Gate","Route","Log","Str","Arr"]:
                to_id=cls.lower()+":"+cls
                typ={"Storage":"Filesystem","DB":"Database","Cache":"Cache","Http":"External"}.get(cls,"Service")
                if not graph.has_node(to_id):
                    graph.add_node(Node(id=to_id, type=typ, name=cls, file="", line=0))
                graph.add_edge(Edge(frm=from_id, to=to_id, kind="DEPENDS_ON", label=cls+"::"))
            elif cls.endswith("Service") or cls.endswith("Repository") or cls.endswith("Manager"):
                to_id="service:"+cls
                if not graph.has_node(to_id):
                    graph.add_node(Node(id=to_id, type="Service", name=cls, file="", line=0))
                graph.add_edge(Edge(frm=from_id, to=to_id, kind="CALLS", label=cls))
            elif cls.endswith("Model") or cls in ["User","Order","Post","Product","Import","Payment"]:
                to_id="model:"+cls
                if not graph.has_node(to_id):
                    graph.add_node(Node(id=to_id, type="Model", name=cls, file="", line=0))
                graph.add_edge(Edge(frm=from_id, to=to_id, kind="WRITES", label=cls))
        # dispatch new Job
        for m in re.finditer(r'dispatch\s*\(\s*new\s+([A-Z][a-zA-Z0-9_\\]+)', clean):
            cls=m.group(1).split("\\")[-1]
            to_id="job:"+cls
            if not graph.has_node(to_id):
                graph.add_node(Node(id=to_id, type="Job", name=cls, file="", line=0))
            graph.add_edge(Edge(frm=from_id, to=to_id, kind="DISPATCHES", label=cls))
        for m in re.finditer(r'event\s*\(\s*new\s+([A-Z][a-zA-Z0-9_\\]+)', clean):
            cls=m.group(1).split("\\")[-1]
            to_id="event:"+cls
            if not graph.has_node(to_id):
                graph.add_node(Node(id=to_id, type="Event", name=cls, file="", line=0))
            graph.add_edge(Edge(frm=from_id, to=to_id, kind="TRIGGERS", label=cls))
        for m in re.finditer(r'([A-Z][a-zA-Z0-9_]+)::observe\s*\(\s*([A-Z][a-zA-Z0-9_\\]+)::class', clean):
            model=m.group(1)
            observer=m.group(2).split("\\")[-1]
            from_m="model:"+model
            to_o="observer:"+observer
            if not graph.has_node(from_m):
                graph.add_node(Node(id=from_m, type="Model", name=model, file="", line=0))
            if not graph.has_node(to_o):
                graph.add_node(Node(id=to_o, type="Observer", name=observer, file="", line=0))
            graph.add_edge(Edge(frm=from_m, to=to_o, kind="TRIGGERS", label="observe"))

class RouteDiscovery:
    def __init__(self, project_root: pathlib.Path):
        self.project_root=project_root

    def discover(self, graph: ApplicationGraph):
        files=self._route_files()
        routes=[]
        for fp in files:
            try:
                content=fp.read_text(errors="ignore")
            except: continue
            rel=str(fp.relative_to(self.project_root))
            # Classic Route::verb('uri', ...)
            for m in re.finditer(r'Route\s*::\s*(get|post|put|patch|delete|options|any|match)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,([^;]+)\)', content, re.I | re.S):
                method=m.group(1).upper()
                uri=m.group(2)
                action_raw=m.group(3)
                line=content[:m.start()].count("\n")+1
                action=self._normalize_action(action_raw)
                routes.append({"method":method,"uri":uri,"action":action,"file":rel,"line":line})
                nid=f"route:{method}:{uri}"
                if not graph.has_node(nid):
                    graph.add_node(Node(id=nid, type="Route", name=f"{method} {uri}", file=rel, line=line, meta={"action":action}))
                if action and "Controller" in action:
                    ctrl=action.split("@")[0].strip(" []'\"")
                    ctrl=ctrl.split("\\")[-1].split("/")[-1]
                    cid=f"controller:{ctrl}"
                    if not graph.has_node(cid):
                        graph.add_node(Node(id=cid, type="Controller", name=ctrl, file="", line=0))
                    graph.add_edge(Edge(frm=nid, to=cid, kind="CALLS", label=action))
            # resource / apiResource
            for m in re.finditer(r'Route\s*::\s*(resource|apiResource)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*([^\s,\)]+)', content, re.I):
                uri=m.group(2)
                ctrl_raw=m.group(3).strip(" []'\"\\")
                ctrl=ctrl_raw.split("\\")[-1].split("/")[-1]
                line=content[:m.start()].count("\n")+1
                methods=["GET","POST","PUT","DELETE"] if m.group(1)=="apiResource" else ["GET","POST","PUT","PATCH","DELETE"]
                for method in methods:
                    nid=f"route:{method}:{uri}"
                    if not graph.has_node(nid):
                        graph.add_node(Node(id=nid, type="Route", name=f"{method} {uri}", file=rel, line=line, meta={"action":ctrl,"resource":True}))
                    cid=f"controller:{ctrl}"
                    if not graph.has_node(cid):
                        graph.add_node(Node(id=cid, type="Controller", name=ctrl, file="", line=0))
                    graph.add_edge(Edge(frm=nid, to=cid, kind="CALLS", label=ctrl))
                routes.append({"method":"|".join(methods),"uri":uri,"action":ctrl,"file":rel,"line":line})
        return {"routes": routes, "count": len(routes)}

    def _route_files(self) -> List[pathlib.Path]:
        candidates=[
            self.project_root / "routes/web.php",
            self.project_root / "routes/api.php",
            self.project_root / "routes/channels.php",
            self.project_root / "routes/console.php",
        ]
        files=[p for p in candidates if p.exists()]
        patterns=[
            "routes/*.php",
            "Modules/*/Routes/*.php","Modules/*/routes/*.php","modules/*/Routes/*.php","modules/*/routes/*.php",
            "app/Modules/*/Routes/*.php","app/Modules/*/routes/*.php",
            "Domain/*/Routes/*.php","domain/*/Routes/*.php","Domains/*/Routes/*.php",
            "src/*/Routes/*.php","src/*/routes/*.php","src/Domain/*/Routes/*.php",
            "packages/*/routes/*.php","packages/*/src/routes/*.php",
            "services/*/routes/*.php","Services/*/Routes/*.php","services/*/app/routes/*.php",
            "apps/*/routes/*.php","microservices/*/routes/*.php",
        ]
        for pat in patterns:
            for p in self.project_root.glob(pat):
                if p not in files:
                    files.append(p)
        return files

    def _normalize_action(self, raw: str) -> str:
        raw=raw.strip()
        m=re.search(r'([A-Za-z0-9_\\]+)::class', raw)
        if m:
            cls=m.group(1)
            mm=re.search(r',\s*[\'"]([^\'"]+)[\'"]', raw)
            if mm: return cls+"@"+mm.group(1)
            return cls
        m=re.search(r'[\'"]([^\'"]+@[^\'"]+)[\'"]', raw)
        if m: return m.group(1)
        if "function" in raw or "fn(" in raw: return "Closure"
        return raw.strip(" \t\n\r\0\x0B,);")
