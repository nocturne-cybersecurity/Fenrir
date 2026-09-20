"""Unauthenticated Memcached version enumeration."""

from __future__ import annotations

import re
import time

from fenrir.core.state import NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult

from ._protocol import (
    bounded_error,
    is_tcp_service,
    mark_attempt,
    open_socket,
    recv_line,
    service_host,
    service_port,
)


class MemcachedEnum(BaseModule):
    name = "memcached_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 59
    _SERVICE_NAMES = {"memcached", "memcache"}

    def can_run(self, state: StateGraph) -> bool:
        return any(
            self._matches(s, state) and not s.data.get("memcached_checked")
            for s in state.find(NodeType.SERVICE)
        )

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            s
            for s in state.find(NodeType.SERVICE)
            if self._matches(s, state) and not s.data.get("memcached_checked")
        ]
        found = 0
        for service in targets:
            mark_attempt(service, "memcached")
            host, port = service_host(service, state), service_port(service)
            if not host or port is None:
                service.data["memcached_error"] = "service host or port unavailable"
                continue
            try:
                line = self._grab(host, port)
                parsed = self.parse_version(line)
                service.data.update(parsed)
                found += 1
            except (OSError, ValueError, TimeoutError, ConnectionError) as exc:
                service.data["memcached_error"] = bounded_error(exc)
        return ModuleResult(True, found, f"{found} servicios Memcached enumerados")

    @classmethod
    def _matches(cls, service, state: StateGraph) -> bool:
        return str(
            service.data.get("name") or ""
        ).lower() in cls._SERVICE_NAMES and is_tcp_service(service, state)

    @staticmethod
    def _grab(host: str, port: int) -> str:
        with open_socket(host, port) as sock:
            sock.sendall(b"version\r\n")
            return (
                recv_line(sock, time.monotonic() + 3).decode(errors="replace").strip()
            )

    @staticmethod
    def parse_version(line: str) -> dict[str, str]:
        line = line.strip()
        match = re.match(r"VERSION\s+([^\s]+)", line, re.IGNORECASE)
        if not match:
            raise ValueError("not a Memcached VERSION response")
        return {
            "memcached_banner": line[:256],
            "memcached_version": match.group(1)[:128],
        }

    _parse_version = parse_version
