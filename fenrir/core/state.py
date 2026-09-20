"""Grafo de conocimiento del engagement."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

import networkx as nx


class NodeType(str, Enum):
    TARGET = "target"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    FINDING = "finding"
    VULN = "vuln"
    VALIDATION = "validation"
    EXPLOIT = "exploit"
    EXPLOIT_RESULT = "exploit_result"
    CREDENTIAL = "credential"
    SESSION = "session"


class FindingStatus(str, Enum):
    POTENTIAL = "potential"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


@dataclass
class Finding:
    """Hallazgo producido por un detector y actualizado por un validator."""

    target: str
    service: str | None
    title: str
    severity: str
    confidence: float
    evidence: list[Any] = field(default_factory=list)
    status: FindingStatus | str = FindingStatus.POTENTIAL
    references: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("finding target must not be empty")
        if not self.title:
            raise ValueError("finding title must not be empty")
        if not 0 <= self.confidence <= 1:
            raise ValueError("finding confidence must be between 0 and 1")
        self.status = FindingStatus(self.status)

    def transition_to(self, status: FindingStatus | str) -> None:
        """Aplica una transición explícita del ciclo de vida del hallazgo."""
        next_status = FindingStatus(status)
        allowed = {
            FindingStatus.POTENTIAL: {
                FindingStatus.CONFIRMED,
                FindingStatus.REJECTED,
            },
            FindingStatus.CONFIRMED: {FindingStatus.REJECTED},
            FindingStatus.REJECTED: set(),
        }
        if next_status not in allowed[self.status]:
            raise ValueError(f"invalid finding transition: {self.status} -> {next_status}")
        self.status = next_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "service": self.service,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "status": self.status.value,
            "references": self.references,
        }


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

    def add_finding(self, finding: Finding) -> Finding:
        """Registra un finding sin modificar el servicio que lo originó."""
        self.add_node(Node(NodeType.FINDING, finding.id, finding.to_dict()))
        return finding

    def add_knowledge_node(self, node_type: NodeType, item: Any, item_id: str) -> Node:
        """Añade una vulnerabilidad o exploit al estado operacional."""
        if node_type not in {NodeType.VULN, NodeType.EXPLOIT}:
            raise ValueError("knowledge nodes must be vulnerabilities or exploits")
        data = item.to_dict()
        return self.add_node(Node(node_type, item_id, data))

    def add_exploit_result(self, result: Any) -> Node:
        return self.add_node(Node(NodeType.EXPLOIT_RESULT, result.id, result.to_dict()))

    def findings(self, **filters: Any) -> list[Finding]:
        return [
            Finding(**{key: value for key, value in node.data.items() if key != "id"}, id=node.id)
            for node in self.find(NodeType.FINDING, **filters)
        ]

    def update_finding_status(
        self, finding_id: str, status: FindingStatus | str
    ) -> Finding:
        node = self.get(finding_id)
        if node is None or node.type != NodeType.FINDING:
            raise KeyError(f"finding not found: {finding_id}")
        finding = Finding(**node.data)
        finding.transition_to(status)
        node.data.update(finding.to_dict())
        return finding

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