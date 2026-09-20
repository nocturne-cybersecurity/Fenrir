"""Contratos para detección y validación de hallazgos."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from fenrir.core.state import Finding, FindingStatus, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class FindingDetector(BaseModule, ABC):
    """Módulo que crea findings potenciales a partir del estado observado."""

    phase: ClassVar[str] = "vulnerability_detection"
    produces: ClassVar[list[NodeType]] = [NodeType.FINDING]

    @abstractmethod
    def detect(self, state: StateGraph) -> list[Finding]:
        """Devuelve findings nuevos sin modificar servicios ni hosts."""

    def run(self, state: StateGraph) -> ModuleResult:
        findings = self.detect(state)
        for finding in findings:
            state.add_finding(finding)
        return ModuleResult(
            success=True,
            added_nodes=len(findings),
            message=f"{len(findings)} findings potenciales",
        )


class FindingValidator(BaseModule, ABC):
    """Módulo que valida findings existentes y cambia solo su ciclo de vida."""

    phase: ClassVar[str] = "validation"
    requires: ClassVar[list[NodeType]] = [NodeType.FINDING]
    produces: ClassVar[list[NodeType]] = [NodeType.FINDING, NodeType.VALIDATION]

    @abstractmethod
    def validate(self, finding: Finding, state: StateGraph) -> FindingStatus:
        """Devuelve el estado resultante del finding."""

    @abstractmethod
    def can_validate(self, finding: Finding) -> bool:
        """Indica si este validator conoce el tipo de evidencia."""

    def can_run(self, state: StateGraph) -> bool:
        return any(
            finding.status == FindingStatus.POTENTIAL
            and self.can_validate(finding)
            for finding in state.findings()
        )

    def run(self, state: StateGraph) -> ModuleResult:
        validated = 0
        for finding in state.findings(status=FindingStatus.POTENTIAL.value):
            if not self.can_validate(finding):
                continue
            state.update_finding_status(finding.id, self.validate(finding, state))
            validated += 1
        return ModuleResult(True, validated, f"{validated} findings validados")
