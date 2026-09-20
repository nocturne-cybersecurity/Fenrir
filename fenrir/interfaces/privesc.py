"""Contrato para descubrimiento de rutas de privilegio, sin ejecución."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from fenrir.core.capabilities import Capability
from fenrir.core.state import NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class PrivEscModule(BaseModule, ABC):
    phase: ClassVar[str] = "privilege_escalation"
    capability: ClassVar[Capability] = Capability.PRIVILEGE_ESCALATION
    requires: ClassVar[list[NodeType]] = [NodeType.SESSION]

    @abstractmethod
    def discover(self, session_id: str, state: StateGraph) -> list[dict]:
        """Devuelve oportunidades para revisión, no las ejecuta."""

    def can_run(self, state: StateGraph) -> bool:
        return bool(state.find(NodeType.SESSION))

    def run(self, state: StateGraph) -> ModuleResult:
        opportunities = sum(
            len(self.discover(session.id, state))
            for session in state.find(NodeType.SESSION)
        )
        return ModuleResult(True, opportunities, f"{opportunities} rutas de privesc descubiertas")
