"""Read-only Redis PING/INFO protocol enumeration."""

from __future__ import annotations

import time
from typing import Any

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


class RedisEnum(BaseModule):
    name = "redis_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 61
    _SERVICE_NAMES = {"redis", "redis-server"}

    def can_run(self, state: StateGraph) -> bool:
        return any(
            self._matches(s, state) and not s.data.get("redis_checked")
            for s in state.find(NodeType.SERVICE)
        )

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            s
            for s in state.find(NodeType.SERVICE)
            if self._matches(s, state) and not s.data.get("redis_checked")
        ]
        found = 0
        for service in targets:
            mark_attempt(service, "redis")
            host, port = service_host(service, state), service_port(service)
            if not host or port is None:
                service.data["redis_error"] = "service host or port unavailable"
                continue
            try:
                service.data.update(self._probe(host, port))
                found += 1
            except (OSError, ValueError, TimeoutError, ConnectionError) as exc:
                service.data["redis_error"] = bounded_error(exc)
        return ModuleResult(True, found, f"{found} servicios Redis enumerados")

    @classmethod
    def _matches(cls, service, state: StateGraph) -> bool:
        return str(
            service.data.get("name") or ""
        ).lower() in cls._SERVICE_NAMES and is_tcp_service(service, state)

    @staticmethod
    def build_command(*parts: str) -> bytes:
        """Build a RESP array command (used for both PING and INFO)."""
        encoded = [f"*{len(parts)}\r\n".encode()]
        for part in parts:
            value = part.encode("utf-8")
            encoded.extend((f"${len(value)}\r\n".encode(), value, b"\r\n"))
        return b"".join(encoded)

    @staticmethod
    def parse_info(payload: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for line in payload.splitlines():
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key in {
                "redis_version",
                "redis_mode",
                "os",
                "arch_bits",
                "process_id",
                "tcp_port",
                "role",
                "run_id",
            }:
                result[key if key.startswith("redis_") else f"redis_{key}"] = value[
                    :256
                ]
        if "redis_version" in result:
            result["redis_server_version"] = result["redis_version"]
        return result

    @classmethod
    def _probe(cls, host: str, port: int) -> dict[str, Any]:
        deadline = time.monotonic() + 5
        with open_socket(host, port) as sock:
            sock.sendall(cls.build_command("PING"))
            response = cls._read_resp(sock, deadline)
            result: dict[str, Any] = {
                "redis_response": str(response)[:128],
                "redis_ping": response == "PONG",
            }
            if response != "PONG":
                return result
            sock.sendall(cls.build_command("INFO", "server"))
            info = cls._read_resp(sock, deadline)
            if isinstance(info, str):
                result.update(cls.parse_info(info))
            return result

    @staticmethod
    def _read_resp(sock, deadline: float) -> Any:
        line = recv_line(sock, deadline)
        if not line:
            raise ConnectionError("empty Redis response")
        prefix, value = line[:1], line[1:].rstrip(b"\r\n")
        if prefix in (b"+", b"-", b":"):
            text = value.decode(errors="replace")
            return int(text) if prefix == b":" else text
        if prefix == b"$":
            length = int(value)
            if length < 0:
                return None
            data = bytearray()
            while len(data) < length + 2:
                chunk = sock.recv(min(length + 2 - len(data), 8192))
                if not chunk:
                    raise ConnectionError("Redis peer closed connection")
                data.extend(chunk)
                if time.monotonic() >= deadline:
                    raise TimeoutError("Redis bulk response timed out")
            return bytes(data[:length]).decode(errors="replace")
        raise ValueError("unsupported Redis response type")

    _parse_info = parse_info
