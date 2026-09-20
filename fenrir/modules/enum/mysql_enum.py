"""Unauthenticated MySQL/MariaDB greeting enumeration."""

from __future__ import annotations

import struct
import time
from typing import Any

from fenrir.core.state import NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult

from ._protocol import (
    bounded_error,
    is_tcp_service,
    mark_attempt,
    open_socket,
    recv_exact,
    service_host,
    service_port,
)


class MySQLEnum(BaseModule):
    name = "mysql_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 61

    _SERVICE_NAMES = {"mysql", "mariadb", "mysql-proxy", "mysqlx"}
    _MARKER = "mysql"

    def can_run(self, state: StateGraph) -> bool:
        return any(
            self._matches(svc, state) and not svc.data.get("mysql_checked")
            for svc in state.find(NodeType.SERVICE)
        )

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if self._matches(svc, state) and not svc.data.get("mysql_checked")
        ]
        found = 0
        for service in targets:
            mark_attempt(service, self._MARKER)
            host, port = service_host(service, state), service_port(service)
            if not host or port is None:
                service.data["mysql_error"] = "service host or port unavailable"
                continue
            try:
                greeting = self._grab(host, port)
                parsed = self.parse_greeting(greeting)
                service.data.update(parsed)
                service.data["mysql_banner"] = parsed.get("mysql_server_version", "")
                found += 1
            except (
                OSError,
                ValueError,
                TimeoutError,
                ConnectionError,
                struct.error,
            ) as exc:
                service.data["mysql_error"] = bounded_error(exc)
        return ModuleResult(True, found, f"{found} servicios MySQL/MariaDB enumerados")

    @classmethod
    def _matches(cls, service, state: StateGraph) -> bool:
        return str(
            service.data.get("name") or ""
        ).lower() in cls._SERVICE_NAMES and is_tcp_service(service, state)

    @staticmethod
    def _grab(host: str, port: int) -> bytes:
        with open_socket(host, port) as sock:
            deadline = time.monotonic() + 3
            header = recv_exact(sock, 4, deadline)
            length = int.from_bytes(header[:3], "little")
            return recv_exact(sock, length, deadline)

    @staticmethod
    def parse_greeting(payload: bytes) -> dict[str, Any]:
        if len(payload) < 5 or payload[0] != 10:
            raise ValueError("not a MySQL protocol 10 greeting")
        offset = 1
        end = payload.find(b"\0", offset)
        if end < 0:
            raise ValueError("truncated MySQL server version")
        version = payload[offset:end].decode("utf-8", errors="replace")
        offset = end + 1
        if len(payload) < offset + 4 + 8 + 1 + 2:
            raise ValueError("truncated MySQL greeting")
        connection_id = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        auth_prefix = payload[offset : offset + 8]
        offset += 9  # auth prefix and filler
        capabilities = struct.unpack_from("<H", payload, offset)[0]
        offset += 2
        result: dict[str, Any] = {
            "mysql_protocol": 10,
            "mysql_server_version": version[:256],
            "mysql_connection_id": connection_id,
            "mysql_capabilities": capabilities,
        }
        if offset >= len(payload):
            return result
        if len(payload) < offset + 1 + 2 + 2 + 1 + 10:
            return result
        result["mysql_status_flags"] = struct.unpack_from("<H", payload, offset + 1)[0]
        result["mysql_charset"] = payload[offset]
        capabilities |= struct.unpack_from("<H", payload, offset + 3)[0] << 16
        result["mysql_capabilities"] = capabilities
        auth_len = payload[offset + 5]
        offset += 16
        if offset < len(payload):
            end = payload.find(b"\0", offset)
            auth_data = payload[offset : end if end >= 0 else len(payload)]
            result["mysql_auth_plugin_data"] = (
                (auth_prefix + auth_data).rstrip(b"\0").hex()
            )
            if end >= 0:
                plugin_start = end + 1
                if plugin_start < len(payload):
                    result["mysql_auth_plugin"] = (
                        payload[plugin_start:]
                        .split(b"\0", 1)[0]
                        .decode("ascii", errors="replace")[:128]
                    )
        elif auth_len:
            result["mysql_auth_plugin_data"] = auth_prefix.hex()
        return result

    _parse_greeting = parse_greeting
