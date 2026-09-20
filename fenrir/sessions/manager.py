"""Gestor central de sesiones activas."""
from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from fenrir.models.session import Session, SessionStatus


class SessionManager:
    """Mantiene registro de todas las sesiones activas."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._counter = 0

    def register(self, session: Session) -> str:
        """Registra una nueva sesión."""
        self._sessions[session.id] = session
        return session.id

    def get(self, session_id: str) -> Session | None:
        """Obtiene una sesión por ID."""
        return self._sessions.get(session_id)

    def remove(self, session_id: str) -> bool:
        """Elimina una sesión. Retorna True si existía."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def update_status(self, session_id: str, status: SessionStatus) -> bool:
        """Actualiza el estado de una sesión."""
        session = self.get(session_id)
        if session is None:
            return False
        # Session es frozen, necesitamos recrearlo
        updated = Session(
            id=session.id,
            target=session.target,
            port=session.port,
            session_type=session.session_type,
            status=status,
            platform=session.platform,
            architecture=session.architecture,
            user=session.user,
            privilege_level=session.privilege_level,
            transport=session.transport,
            created_by=session.created_by,
            pid=session.pid,
            created_at=session.created_at,
            last_seen=datetime.now(UTC),
            metadata=session.metadata,
        )
        self._sessions[session_id] = updated
        return True

    def list_active(self) -> list[Session]:
        """Lista todas las sesiones activas."""
        return [s for s in self._sessions.values() if s.is_alive()]

    def list_by_target(self, target: str) -> list[Session]:
        """Lista sesiones para un objetivo específico."""
        return [s for s in self._sessions.values() if s.target == target]

    def list_by_type(self, session_type: str) -> list[Session]:
        """Lista sesiones por tipo."""
        return [s for s in self._sessions.values() if s.session_type.value == session_type]

    def cleanup_dead(self, timeout_seconds: int = 300) -> int:
        """Elimina sesiones muertas o zombies antiguas."""
        now = datetime.now(UTC)
        to_remove = []
        for session_id, session in self._sessions.items():
            if session.status in (SessionStatus.DEAD, SessionStatus.DISCONNECTED, SessionStatus.ZOMBIE):
                age = (now - session.last_seen).total_seconds()
                if age > timeout_seconds:
                    to_remove.append(session_id)
        for session_id in to_remove:
            self.remove(session_id)
        return len(to_remove)

    def to_dict(self) -> dict[str, Any]:
        """Exporta estado completo."""
        return {
            "total": len(self._sessions),
            "active": len(self.list_active()),
            "sessions": [s.to_dict() for s in self._sessions.values()],
        }

    def __iter__(self) -> Iterator[Session]:
        return iter(self._sessions.values())

    def __len__(self) -> int:
        return len(self._sessions)
