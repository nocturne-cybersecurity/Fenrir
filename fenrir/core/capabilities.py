from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Capability(StrEnum):
    READ_ONLY = "read_only"
    ACTIVE_SCAN = "active_scan"
    VALIDATION = "validation"
    EXPLOIT = "exploit"
    EXECUTE = "execute"
    SESSION = "session"
    POST_EXPLOITATION = "post_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass(frozen=True)
class ExecutionPolicy:
    """Límites de ejecución para el scheduler y los módulos."""

    max_capability: Capability = Capability.VALIDATION

    def allows(self, capability: Capability) -> bool:
        order = list(Capability)
        return order.index(capability) <= order.index(self.max_capability)

    @classmethod
    def from_flags(
        cls, *, exploit: bool = False, execute: bool = False, post: bool = False, privesc: bool = False
    ) -> ExecutionPolicy:
        if privesc:
            return cls(Capability.PRIVILEGE_ESCALATION)
        if post:
            return cls(Capability.POST_EXPLOITATION)
        if execute:
            return cls(Capability.EXECUTE)
        if exploit:
            return cls(Capability.EXPLOIT)
        return cls()
