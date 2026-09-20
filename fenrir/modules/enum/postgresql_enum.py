"""Unauthenticated PostgreSQL protocol and authentication negotiation enumeration."""

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


class PostgreSQLEnum(BaseModule):
    name = "postgresql_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 61
    _SERVICE_NAMES = {"postgresql", "postgres", "pgsql"}

    def can_run(self, state: StateGraph) -> bool:
        return any(
            self._matches(s, state) and not s.data.get("postgresql_checked")
            for s in state.find(NodeType.SERVICE)
        )

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            s
            for s in state.find(NodeType.SERVICE)
            if self._matches(s, state) and not s.data.get("postgresql_checked")
        ]
        found = 0
        for service in targets:
            mark_attempt(service, "postgresql")
            host, port = service_host(service, state), service_port(service)
            if not host or port is None:
                service.data["postgresql_error"] = "service host or port unavailable"
                continue
            try:
                service.data.update(self._probe(host, port))
                found += 1
            except (
                OSError,
                ValueError,
                TimeoutError,
                ConnectionError,
                struct.error,
            ) as exc:
                service.data["postgresql_error"] = bounded_error(exc)
        return ModuleResult(True, found, f"{found} servicios PostgreSQL enumerados")

    @classmethod
    def _matches(cls, service, state: StateGraph) -> bool:
        return str(
            service.data.get("name") or ""
        ).lower() in cls._SERVICE_NAMES and is_tcp_service(service, state)

    @staticmethod
    def build_ssl_request() -> bytes:
        return struct.pack("!II", 8, 80877103)

    @staticmethod
    def build_startup_packet(user: str = "fenrir", database: str = "postgres") -> bytes:
        params = (
            b"user\0"
            + user.encode("utf-8")
            + b"\0database\0"
            + database.encode("utf-8")
            + b"\0"
        )
        params += b"client_encoding\0UTF8\0\0"
        return struct.pack("!II", 8 + len(params), 196608) + params

    @classmethod
    def _probe(cls, host: str, port: int) -> dict[str, Any]:
        deadline = time.monotonic() + 4
        result: dict[str, Any] = {"postgresql_protocol": "3.0"}
        with open_socket(host, port, timeout=3) as sock:
            sock.sendall(cls.build_ssl_request())
            response = recv_exact(sock, 1, deadline)
            if response == b"S":
                result["postgresql_ssl_supported"] = True
                return result
            if response not in (b"N", b""):
                raise ValueError("invalid PostgreSQL SSL negotiation response")
            result["postgresql_ssl_supported"] = False
            sock.sendall(cls.build_startup_packet())
            parameters: dict[str, str] = {}
            for _ in range(8):
                header = recv_exact(sock, 5, deadline)
                length = struct.unpack("!I", header[1:])[0]
                if length < 4 or length > 65536:
                    raise ValueError("invalid PostgreSQL message length")
                body = recv_exact(sock, length - 4, deadline)
                kind = header[:1]
                if kind == b"R" and len(body) >= 4:
                    auth_code = struct.unpack("!I", body[:4])[0]
                    result["postgresql_auth_method"] = {
                        0: "ok",
                        2: "kerberos",
                        3: "cleartext",
                        5: "md5",
                        10: "sasl",
                        11: "sasl-continue",
                        12: "sasl-final",
                    }.get(auth_code, f"code-{auth_code}")
                    if auth_code != 0:
                        break
                elif kind == b"S":
                    fields = body.split(b"\0")
                    if len(fields) >= 2 and fields[0]:
                        parameters[fields[0].decode(errors="replace")[:128]] = fields[
                            1
                        ].decode(errors="replace")[:256]
                elif kind == b"K" and len(body) >= 8:
                    result["postgresql_backend_pid"] = struct.unpack("!I", body[:4])[0]
                elif kind == b"Z":
                    break
                elif kind == b"E":
                    result["postgresql_error"] = cls._parse_error(body)
                    break
            if parameters:
                result["postgresql_parameters"] = parameters
                if parameters.get("server_version"):
                    result["postgresql_server_version"] = parameters["server_version"]
        return result

    @staticmethod
    def _parse_error(body: bytes) -> str:
        parts = body.split(b"\0")
        messages = []
        for part in parts:
            if len(part) > 1 and part[:1] in b"SMCV":
                messages.append(part[1:].decode(errors="replace"))
        return "; ".join(messages)[:512]

    parse_error = _parse_error
