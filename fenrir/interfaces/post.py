"""Contrato para módulos post-explotación de solo lectura."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from fenrir.core.capabilities import Capability
from fenrir.core.state import NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class PostModule(BaseModule, ABC):
    phase: ClassVar[str] = "post_exploitation"
    capability: ClassVar[Capability] = Capability.POST_EXPLOITATION
    requires: ClassVar[list[NodeType]] = [NodeType.SESSION]

    @abstractmethod
    def inspect(self, session_id: str, state: StateGraph) -> dict:
        """Inspecciona metadata ya disponible; no ejecuta comandos remotos."""

    def can_run(self, state: StateGraph) -> bool:
        return bool(state.find(NodeType.SESSION))

    def run(self, state: StateGraph) -> ModuleResult:
        count = 0
        for session in state.find(NodeType.SESSION):
            session.data.setdefault("post", {}).update(self.inspect(session.id, state))
            count += 1
        return ModuleResult(True, count, f"{count} sesiones inspeccionadas")
