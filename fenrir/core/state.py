"""Grafo de conocimiento del engagement."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import networkx as nx


class NodeType(str, Enum):
    TARGET = "target"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    VULN = "vuln"
    CREDENTIAL = "credential"
    SESSION = "session"


@dataclass
class Node:
    type: NodeType
    id: str
    data: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.type, self.id))


class StateGraph:
    """Todo lo que descubren los módulos se vuelca aquí. El engine
    y las reglas leen de aquí para decidir el siguiente paso."""

    def __init__(self) -> None:
        self.g: nx.DiGraph = nx.DiGraph()
        self._index: dict[str, Node] = {}

    # ---------- API pública ----------
    def add_node(self, node: Node) -> Node:
        existing = self._index.get(node.id)
        if existing:
            existing.data.update(node.data)
            return existing
        self.g.add_node(node.id, type=node.type.value)
        self._index[node.id] = node
        return node

    def add_edge(self, src: str, dst: str, relation: str) -> None:
        if src in self._index and dst in self._index:
            self.g.add_edge(src, dst, relation=relation)

    def get(self, node_id: str) -> Node | None:
        return self._index.get(node_id)

    def find(self, node_type: NodeType, **filters: Any) -> list[Node]:
        out = []
        for n in self._index.values():
            if n.type != node_type:
                continue
            if all(n.data.get(k) == v for k, v in filters.items()):
                out.append(n)
        return out

    def has(self, node_type: NodeType, **filters: Any) -> bool:
        return bool(self.find(node_type, **filters))

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n.id, "type": n.type.value, "data": n.data}
                for n in self._index.values()
            ],
            "edges": [
                {"src": u, "dst": v, "relation": d["relation"]}
                for u, v, d in self.g.edges(data=True)
            ],
        }

    def __len__(self) -> int:
        return len(self._index)