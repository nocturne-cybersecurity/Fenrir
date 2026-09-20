"""Contrato que todo módulo debe cumplir."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from fenrir.core.state import NodeType, StateGraph


@dataclass
class ModuleResult:
    success: bool
    added_nodes: int = 0
    message: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class BaseModule(ABC):
    """Todos los módulos heredan de aquí.

    Cada módulo declara:
      - name: identificador único
      - phase: recon | enum | exploit | privesc | post
      - requires: tipos de nodo que necesita del estado
      - produces: tipos de nodo que añade
      - priority: mayor = antes se ejecuta (0-100)
    """

    name: ClassVar[str]
    phase: ClassVar[str] = "recon"
    requires: ClassVar[list[NodeType]] = []
    produces: ClassVar[list[NodeType]] = []
    priority: ClassVar[int] = 50

    @abstractmethod
    def can_run(self, state: StateGraph) -> bool:
        """¿Hay suficiente info en el estado para ejecutarme?"""

    @abstractmethod
    def run(self, state: StateGraph) -> ModuleResult:
        """Ejecuta la lógica y vuelca resultados en el estado."""

    def score(self, state: StateGraph) -> float:
        """Heurística de prioridad. Sobrescribible por módulo."""
        return float(self.priority)