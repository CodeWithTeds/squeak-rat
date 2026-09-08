from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass(slots=True)
class Node:
    id: str
    type: str  # Route|Controller|Middleware|Service|Model|Job|Event|Listener|Observer|Database|External|Filesystem|Cache|Other
    name: str
    file: str = ""
    line: int = 0
    meta: dict = field(default_factory=dict)

    def to_dict(self):
        return {"id": self.id, "type": self.type, "name": self.name, "file": self.file, "line": self.line, "meta": self.meta}

@dataclass(slots=True)
class Edge:
    frm: str
    to: str
    kind: str  # CALLS|DISPATCHES|DEPENDS_ON etc.
    label: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self):
        return {"from": self.frm, "to": self.to, "kind": self.kind, "label": self.label, "meta": self.meta}

class ApplicationGraph:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []

    def add_node(self, node: Node):
        self.nodes[node.id] = node

    def has_node(self, nid: str) -> bool:
        return nid in self.nodes

    def get_node(self, nid: str) -> Optional[Node]:
        return self.nodes.get(nid)

    def add_edge(self, edge: Edge):
        self.edges.append(edge)

    def nodes_by_type(self, t: str) -> List[Node]:
        return [n for n in self.nodes.values() if n.type == t]

    def outgoing(self, nid: str) -> List[Edge]:
        return [e for e in self.edges if e.frm == nid]

    def incoming(self, nid: str) -> List[Edge]:
        return [e for e in self.edges if e.to == nid]

    def reachable_from(self, start: str, depth: int = 10) -> List[Node]:
        visited={start:True}
        queue=[(start,0)]
        res=[]
        while queue:
            cur,d = queue.pop(0)
            if d>=depth: continue
            for e in self.outgoing(cur):
                if e.to not in visited:
                    visited[e.to]=True
                    n=self.get_node(e.to)
                    if n: res.append(n)
                    queue.append((e.to,d+1))
        return res

    def ancestors_of(self, nid: str, depth: int=10) -> List[Node]:
        visited={nid:True}
        queue=[(nid,0)]
        res=[]
        while queue:
            cur,d=queue.pop(0)
            if d>=depth: continue
            for e in self.incoming(cur):
                if e.frm not in visited:
                    visited[e.frm]=True
                    n=self.get_node(e.frm)
                    if n: res.append(n)
                    queue.append((e.frm,d+1))
        return res

    def find_by_name(self, name: str) -> Optional[Node]:
        needle=name.lower()
        base=name.split("/")[-1].split("\\")[-1].replace(".php","").lower()
        # exact
        for n in self.nodes.values():
            if n.name.lower()==needle or n.name.lower()==base:
                return n
        for n in self.nodes.values():
            if base and base in n.name.lower():
                return n
        for n in self.nodes.values():
            if needle in n.id.lower() or needle in n.name.lower():
                return n
        return None

    def impact_for(self, nid: str):
        direct_edges=self.incoming(nid)
        direct_nodes=[self.get_node(e.frm) for e in direct_edges]
        direct_nodes=[n for n in direct_nodes if n]
        ancestors=self.ancestors_of(nid, depth=8)
        def group(ns): 
            d={}
            for n in ns:
                d[n.type]=d.get(n.type,0)+1
            return d
        total=len(direct_nodes)*3+len(ancestors)
        score="INFO"
        if total>=40: score="CRITICAL"
        elif total>=20: score="HIGH"
        elif total>=8: score="MEDIUM"
        elif total>=3: score="LOW"
        return {"direct": direct_nodes, "direct_by_type": group(direct_nodes), "indirect": ancestors, "indirect_by_type": group(ancestors), "score": score}

    def to_dict(self):
        return {"nodes":[n.to_dict() for n in self.nodes.values()], "edges":[e.to_dict() for e in self.edges], "stats": self.stats()}

    def stats(self):
        by={}
        for n in self.nodes.values():
            by[n.type]=by.get(n.type,0)+1
        return {"nodes": len(self.nodes), "edges": len(self.edges), "by_type": by}
