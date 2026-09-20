from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """Observación que respalda una detección o validación."""

    source: str
    value: Any
    field: str | None = None
    collected_at: str | None = None
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "field": self.field,
            "value": self.value,
            "collected_at": self.collected_at,
            "metadata": self.metadata,
        }
