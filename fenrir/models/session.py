"""Modelo de sesión activa tras explotación exitosa."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class SessionType(Enum):
    SHELL = "shell"
    BIND = "bind"
    REVERSE = "reverse"
    WEB = "web"
    SMB = "smb"
    SSH = "ssh"
    RDP = "rdp"
    CUSTOM = "custom"


class SessionStatus(Enum):
    CREATED = "created"
    ACTIVE = "active"
    DEAD = "dead"
    DISCONNECTED = "disconnected"
    ZOMBIE = "zombie"
    CLOSED = "closed"


@dataclass(frozen=True)
class Session:
    """Representa una sesión activa tras explotación exitosa."""

    id: str
    target: str
    port: int
    session_type: SessionType
    status: SessionStatus = SessionStatus.ACTIVE
    platform: str = "unknown"
    architecture: str = "unknown"
    user: str = "unknown"
    privilege_level: str = "unknown"
    transport: str = "unknown"
    created_by: str | None = None
    pid: int | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "port": self.port,
            "session_type": self.session_type.value,
            "status": self.status.value,
            "platform": self.platform,
            "architecture": self.architecture,
            "user": self.user,
            "privilege_level": self.privilege_level,
            "transport": self.transport,
            "created_by": self.created_by,
            "pid": self.pid,
            "created_at": self.created_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "metadata": self.metadata,
        }

    def is_alive(self) -> bool:
        return self.status == SessionStatus.ACTIVE

    def age_seconds(self) -> int:
        return int((datetime.now(UTC) - self.created_at).total_seconds())
