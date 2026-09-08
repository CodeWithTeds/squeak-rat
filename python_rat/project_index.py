"""
project_index.py — Project Index (Plan #5)
Builds a project-wide index connecting:
 Routes -> Controllers -> Services -> Models -> Queries -> Views
Allows vulnerabilities to be detected across multiple files instead of per-file.
"""
from __future__ import annotations
import re
import pathlib
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from functools import lru_cache
from .graph import ApplicationGraph, Node, Edge
from .ast_parser import PhpAstParser, ParserConfig

@dataclass
class ClassInfo:
    name: str
    file: str
    type: str  # Controller, Service, Model, etc.
    methods: List[str] = field(default_factory=list)
    parents: List[str] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    uses: List[str] = field(default_factory=list)
    line: int = 1

@dataclass
class RouteInfo:
    method: str
    uri: str
    action: str
    controller: str
    func: str
    file: str
    line: int
    middleware: List[str] = field(default_factory=list)

class ProjectIndex:
    """
    Entire project indexing — for interprocedural analysis (Plan #4, #5, #6)
    Represents application behavior as graphs: where data originates, travels, affects, ends up.
    """
    def __init__(self, project_root: pathlib.Path, parser: Optional[PhpAstParser] = None):
        self.project_root = pathlib.Path(project_root).resolve()
        self.parser = parser or PhpAstParser(self.project_root, ParserConfig(cache_enabled=True))
        self.classes: Dict[str, ClassInfo] = {}
        self.routes: List[RouteInfo] = []
        self.file_to_class: Dict[str, str] = {}
        self.class_to_file: Dict[str, str] = {}
        self.method_calls: Dict[str, List[Tuple[str, int]]] = {}  # class -> [(called_class.method, line)]
        self._built = False

    def build(self, php_files: List[pathlib.Path], graph: Optional[ApplicationGraph] = None) -> ApplicationGraph:
        """Batch build index — uses batch AST parsing (performance Pattern #12, #14)."""
        if graph is None:
            graph = ApplicationGraph()

        # Batch parse all files (with cache)
        parsed = self.parser.parse_batch(php_files, workers=4)

        for pf in parsed:
            if pf.error and "skipped" in pf.error:
                continue
            rel = pf.file
            # Infer class type from file path + parsed classes
            for cls in pf.classes:
                # Determine type via file path heuristics + AST
                typ = self._infer_type(rel, cls, pf.methods)
                ci = ClassInfo(name=cls, file=rel, type=typ, methods=pf.methods, uses=pf.uses)
                self.classes[cls] = ci
                self.file_to_class[rel] = cls
                self.class_to_file[cls] = rel
                # Add to graph
                nid = f"{typ.lower()}:{cls}"
                if not graph.has_node(nid):
                    graph.add_node(Node(id=nid, type=typ, name=cls, file=rel, line=1))

        # Second pass: resolve edges via content scanning (but using cached content reads, batch)
        # For performance: use generator to avoid loading all at once (Pattern 19)
        for pf in parsed:
            if not pf.nodes:
                continue
            # Read raw once for call detection (batch I/O already done via parser, but we need content for calls)
            # Use weak cache: store file content in lru
            try:
                content = (self.project_root / pf.file).read_text(errors="ignore") if (self.project_root / pf.file).exists() else ""
            except:
                content = ""
            if not content:
                continue
            src_cls = self.file_to_class.get(pf.file, "")
            if not src_cls:
                continue
            src_typ = self.classes[src_cls].type if src_cls in self.classes else "Other"
            src_id = f"{src_typ.lower()}:{src_cls}"
            # Extract calls via regex on stripped? but we have nodes
            # Use lightweight call extraction
            for m in re.finditer(r'\b([A-Z][a-zA-Z0-9_\\]+)\s*::\s*([a-zA-Z_]\w*)\s*\(|->\s*([a-zA-Z_]\w*)\s*\(|new\s+([A-Z][a-zA-Z0-9_\\]+)\s*\(|dispatch\s*\(\s*new\s+([A-Z][a-zA-Z0-9_\\]+)', content):
                # For simplicity, extract any class-like token
                cls_token = m.group(1) or m.group(4) or m.group(5)
                if cls_token:
                    cls_token = cls_token.split("\\")[-1]
                    if cls_token in self.classes:
                        dst_typ = self.classes[cls_token].type
                        dst_id = f"{dst_typ.lower()}:{cls_token}"
                        if not graph.has_node(dst_id):
                            graph.add_node(Node(id=dst_id, type=dst_typ, name=cls_token, file=self.class_to_file.get(cls_token, ""), line=1))
                        graph.add_edge(Edge(frm=src_id, to=dst_id, kind="CALLS", label=cls_token))

        # Discover routes separately (need route files)
        self._discover_routes(graph)

        self._built = True
        return graph

    def _discover_routes(self, graph: ApplicationGraph):
        """Enrich with route discovery (same as discovery.py but using index)."""
        route_files = self._route_files()
        _middleware_re = re.compile(r'middleware\s*\(\s*[\'"]([^\'"]+)[\'"]')
        for fp in route_files:
            try:
                content = fp.read_text(errors="ignore")
                rel = str(fp.relative_to(self.project_root))
            except:
                continue
            # Classic Route::verb
            for m in re.finditer(r'Route\s*::\s*(get|post|put|patch|delete|options|any|match)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,([^;]+)\)', content, re.I | re.S):
                method = m.group(1).upper()
                uri = m.group(2)
                action_raw = m.group(3)
                line = content[:m.start()].count("\n") + 1
                action = self._normalize_action(action_raw)
                controller = action.split("@")[0].split("\\")[-1].strip(" []'\"") if "@" in action else action.split("\\")[-1].strip(" []'\"")
                # Middleware around
                win = content[max(0, m.start()-800): m.start()+500]
                mws = _middleware_re.findall(win)
                ri = RouteInfo(method=method, uri=uri, action=action, controller=controller, func=action.split("@")[1] if "@" in action else "", file=rel, line=line, middleware=mws)
                self.routes.append(ri)
                nid = f"route:{method}:{uri}"
                if not graph.has_node(nid):
                    graph.add_node(Node(id=nid, type="Route", name=f"{method} {uri}", file=rel, line=line, meta={"action": action}))
                if controller and "Controller" in controller:
                    cid = f"controller:{controller}"
                    if not graph.has_node(cid):
                        # Check if controller exists in index
                        if controller in self.classes:
                            typ = self.classes[controller].type
                            cid = f"{typ.lower()}:{controller}"
                        else:
                            graph.add_node(Node(id=cid, type="Controller", name=controller, file="", line=0))
                    graph.add_edge(Edge(frm=nid, to=cid, kind="CALLS", label=action))
            # resource
            for m in re.finditer(r'Route\s*::\s*(resource|apiResource)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*([^\s,\)]+)', content, re.I):
                uri = m.group(2)
                ctrl_raw = m.group(3).strip(" []'\"\\")
                ctrl = ctrl_raw.split("\\")[-1].split("/")[-1]
                line = content[:m.start()].count("\n") + 1
                for method in (["GET","POST","PUT","DELETE"] if m.group(1)=="apiResource" else ["GET","POST","PUT","PATCH","DELETE"]):
                    nid = f"route:{method}:{uri}"
                    if not graph.has_node(nid):
                        graph.add_node(Node(id=nid, type="Route", name=f"{method} {uri}", file=rel, line=line, meta={"action": ctrl, "resource": True}))
                    cid = f"controller:{ctrl}"
                    if not graph.has_node(cid):
                        graph.add_node(Node(id=cid, type="Controller", name=ctrl, file="", line=0))
                    graph.add_edge(Edge(frm=nid, to=cid, kind="CALLS", label=ctrl))
                self.routes.append(RouteInfo(method="|".join(["GET","POST","PUT","DELETE"]), uri=uri, action=ctrl, controller=ctrl, func="", file=rel, line=line))

    def _route_files(self) -> List[pathlib.Path]:
        candidates = [
            self.project_root / "routes/web.php",
            self.project_root / "routes/api.php",
            self.project_root / "routes/channels.php",
            self.project_root / "routes/console.php",
        ]
        files = [p for p in candidates if p.exists()]
        patterns = [
            "routes/*.php",
            "Modules/*/Routes/*.php","Modules/*/routes/*.php","modules/*/Routes/*.php","modules/*/routes/*.php",
            "app/Modules/*/Routes/*.php","app/Modules/*/routes/*.php",
            "Domain/*/Routes/*.php","domain/*/Routes/*.php","Domains/*/Routes/*.php",
            "src/*/Routes/*.php","src/*/routes/*.php",
            "packages/*/routes/*.php","packages/*/src/routes/*.php",
            "services/*/routes/*.php","Services/*/Routes/*.php","services/*/app/routes/*.php",
            "apps/*/routes/*.php","microservices/*/routes/*.php",
        ]
        for pat in patterns:
            for p in self.project_root.glob(pat):
                if p not in files:
                    files.append(p)
        return files

    def _infer_type(self, file_path: str, class_name: str, methods: List[str]) -> str:
        lower = file_path.lower()
        if "/http/controllers" in lower or class_name.endswith("Controller"):
            return "Controller"
        if "/models" in lower or "/entities" in lower or class_name.endswith("Model") or "extends Model" in class_name:
            return "Model"
        if "extends Model" in str(methods):
            return "Model"
        if "/services" in lower or class_name.endswith("Service"):
            return "Service"
        if "/repositories" in lower or class_name.endswith("Repository"):
            return "Repository"
        if "/jobs" in lower or class_name.endswith("Job"):
            return "Job"
        if "/events" in lower or class_name.endswith("Event"):
            return "Event"
        if "/listeners" in lower or class_name.endswith("Listener"):
            return "Listener"
        if "/observers" in lower or class_name.endswith("Observer"):
            return "Observer"
        if "/middleware" in lower or class_name.endswith("Middleware"):
            return "Middleware"
        if "/notifications" in lower or class_name.endswith("Notification"):
            return "Notification"
        if class_name.endswith("Request") and "Request" in file_path:
            return "Request"
        if class_name.endswith("Policy"):
            return "Policy"
        return "Other"

    def _normalize_action(self, raw: str) -> str:
        raw = raw.strip()
        m = re.search(r'([A-Za-z0-9_\\]+)::class', raw)
        if m:
            cls = m.group(1)
            mm = re.search(r',\s*[\'"]([^\'"]+)[\'"]', raw)
            if mm:
                return cls + "@" + mm.group(1)
            return cls
        m = re.search(r'[\'"]([^\'"]+@[^\'"]+)[\'"]', raw)
        if m:
            return m.group(1)
        if "function" in raw or "fn(" in raw:
            return "Closure"
        return raw.strip(" \t\n\r\0\x0B,);")

    @lru_cache(maxsize=512)
    def get_class(self, name: str) -> Optional[ClassInfo]:
        return self.classes.get(name)

    @lru_cache(maxsize=512)
    def is_controller(self, class_name: str) -> bool:
        ci = self.classes.get(class_name)
        return ci.type == "Controller" if ci else class_name.endswith("Controller")

    def stats(self) -> Dict:
        by_type: Dict[str, int] = {}
        for ci in self.classes.values():
            by_type[ci.type] = by_type.get(ci.type, 0) + 1
        return {"classes": len(self.classes), "routes": len(self.routes), "by_type": by_type}
