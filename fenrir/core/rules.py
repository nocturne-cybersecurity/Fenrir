"""Motor de reglas simple: decide qué módulos disparar según el estado actual.

Ejemplo de idea: "si se descubre un puerto 80/443 abierto -> disparar
http_probe"; "si http_probe detecta un login panel -> anotar hallazgo".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fenrir.core.state import KnowledgeGraph


@dataclass
class Rule:
    """Una regla: condición sobre el estado + acción a disparar."""

    name: str
    condition: Callable[[KnowledgeGraph], bool]
    action: Callable[[KnowledgeGraph], None]


class RuleEngine:
    """Evalúa un conjunto de reglas contra el estado actual."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def evaluate(self, state: KnowledgeGraph) -> None:
        """Recorre las reglas registradas y dispara las que apliquen."""
        raise NotImplementedError
