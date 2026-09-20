"""Unauthenticated LDAP anonymous-bind handshake enumeration."""

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
    recv_exact,
    service_host,
    service_port,
)


def _ber_length(size: int) -> bytes:
    if size < 128:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(value)) + value


def _read_ber_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated BER length")
    first = data[offset]
    if first < 128:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 4 or offset + 1 + count > len(data):
        raise ValueError("invalid BER length")
    return int.from_bytes(
        data[offset + 1 : offset + 1 + count], "big"
    ), offset + 1 + count


class LDAPEnum(BaseModule):
    name = "ldap_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 59
    _SERVICE_NAMES = {"ldap"}

    def can_run(self, state: StateGraph) -> bool:
        return any(
            self._matches(s, state) and not s.data.get("ldap_checked")
            for s in state.find(NodeType.SERVICE)
        )

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            s
            for s in state.find(NodeType.SERVICE)
            if self._matches(s, state) and not s.data.get("ldap_checked")
        ]
        found = 0
        for service in targets:
            mark_attempt(service, "ldap")
            host, port = service_host(service, state), service_port(service)
            if not host or port is None:
                service.data["ldap_error"] = "service host or port unavailable"
                continue
            try:
                service.data.update(self._probe(host, port))
                found += 1
            except (OSError, ValueError, TimeoutError, ConnectionError) as exc:
                service.data["ldap_error"] = bounded_error(exc)
        return ModuleResult(True, found, f"{found} servicios LDAP enumerados")

    @classmethod
    def _matches(cls, service, state: StateGraph) -> bool:
        return str(
            service.data.get("name") or ""
        ).lower() in cls._SERVICE_NAMES and is_tcp_service(service, state)

    @staticmethod
    def build_anonymous_bind(message_id: int = 1) -> bytes:
        version = _ber_tlv(0x02, b"\x03")
        name = _ber_tlv(0x04, b"")
        simple_password = _ber_tlv(0x80, b"")
        bind = _ber_tlv(0x60, version + name + simple_password)
        return _ber_tlv(0x30, _ber_tlv(0x02, bytes([message_id])) + bind)

    @classmethod
    def _probe(cls, host: str, port: int) -> dict[str, Any]:
        with open_socket(host, port) as sock:
            sock.sendall(cls.build_anonymous_bind())
            deadline = time.monotonic() + 4
            first = recv_exact(sock, 2, deadline)
            if first[0] != 0x30:
                raise ValueError("invalid LDAP response")
            length = first[1]
            if length & 0x80:
                count = length & 0x7F
                length = int.from_bytes(recv_exact(sock, count, deadline), "big")
            body = recv_exact(sock, length, deadline)
        return cls.parse_bind_response(body)

    @staticmethod
    def parse_bind_response(body: bytes) -> dict[str, Any]:
        if len(body) < 2 or body[0] != 0x02:
            raise ValueError("invalid LDAP message id")
        message_id_length, offset = _read_ber_length(body, 1)
        offset += message_id_length
        if offset >= len(body) or body[offset] != 0x61:
            raise ValueError("LDAP response is not bindResponse")
        tag_len, start = _read_ber_length(body, offset + 1)
        response = body[start : start + tag_len]
        if len(response) < 2 or response[0] not in (0x0A, 0x02):
            raise ValueError("invalid LDAP result code")
        code_len, code_start = _read_ber_length(response, 1)
        if code_start + code_len > len(response):
            raise ValueError("truncated LDAP result code")
        code = int.from_bytes(response[code_start : code_start + code_len], "big")
        return {"ldap_result_code": code, "ldap_anonymous_bind": code == 0}

    _parse_bind_response = parse_bind_response
