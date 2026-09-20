"""Unauthenticated MongoDB hello enumeration using Mongo wire protocol."""

from __future__ import annotations

import struct
import time
from typing import Any

from fenrir.core.state import NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult

from ._protocol import (
    bounded_error,
    compact_metadata,
    is_tcp_service,
    mark_attempt,
    open_socket,
    recv_exact,
    service_host,
    service_port,
)


def _cstring(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if b"\0" in encoded:
        raise ValueError("BSON strings cannot contain NUL")
    return encoded + b"\0"


def _bson_document(values: dict[str, Any]) -> bytes:
    elements = bytearray()
    for key, value in values.items():
        if isinstance(value, bool):
            elements.extend(b"\x08" + _cstring(key) + (b"\x01" if value else b"\0"))
        elif isinstance(value, int):
            elements.extend(b"\x10" + _cstring(key) + struct.pack("<i", value))
        elif isinstance(value, str):
            encoded = value.encode("utf-8")
            elements.extend(
                b"\x02"
                + _cstring(key)
                + struct.pack("<i", len(encoded) + 1)
                + encoded
                + b"\0"
            )
        else:
            raise TypeError(f"unsupported BSON value for {key}")
    size = len(elements) + 5
    return struct.pack("<i", size) + elements + b"\0"


class MongoDBEnum(BaseModule):
    name = "mongodb_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 61
    _SERVICE_NAMES = {"mongodb", "mongo", "mongod"}

    def can_run(self, state: StateGraph) -> bool:
        return any(
            self._matches(s, state) and not s.data.get("mongodb_checked")
            for s in state.find(NodeType.SERVICE)
        )

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            s
            for s in state.find(NodeType.SERVICE)
            if self._matches(s, state) and not s.data.get("mongodb_checked")
        ]
        found = 0
        for service in targets:
            mark_attempt(service, "mongodb")
            host, port = service_host(service, state), service_port(service)
            if not host or port is None:
                service.data["mongodb_error"] = "service host or port unavailable"
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
                service.data["mongodb_error"] = bounded_error(exc)
        return ModuleResult(True, found, f"{found} servicios MongoDB enumerados")

    @classmethod
    def _matches(cls, service, state: StateGraph) -> bool:
        return str(
            service.data.get("name") or ""
        ).lower() in cls._SERVICE_NAMES and is_tcp_service(service, state)

    @staticmethod
    def build_op_msg(request_id: int = 1) -> bytes:
        document = _bson_document({"hello": 1, "helloOk": True, "$db": "admin"})
        body = struct.pack("<I", 0) + b"\0" + document
        return struct.pack("<iiii", 16 + len(body), request_id, 0, 2013) + body

    @staticmethod
    def build_query(request_id: int = 1) -> bytes:
        """Legacy OP_QUERY fallback for pre-3.6 MongoDB servers."""
        query = _bson_document({"isMaster": 1, "$db": "admin"})
        namespace = b"admin.$cmd\0"
        body = struct.pack("<i", 0) + namespace + struct.pack("<ii", 0, 1) + query
        return struct.pack("<iiii", 16 + len(body), request_id, 0, 2004) + body

    @classmethod
    def _probe(cls, host: str, port: int) -> dict[str, Any]:
        response = cls._request(host, port, cls.build_op_msg())
        if response is None:
            response = cls._request(host, port, cls.build_query())
        if not response:
            raise ValueError("MongoDB returned no hello document")
        result: dict[str, Any] = {"mongodb_hello": compact_metadata(response)}
        for source, target in (
            ("version", "mongodb_server_version"),
            ("maxWireVersion", "mongodb_max_wire_version"),
            ("minWireVersion", "mongodb_min_wire_version"),
            ("isWritablePrimary", "mongodb_writable_primary"),
            ("ismaster", "mongodb_is_master"),
        ):
            if source in response:
                result[target] = response[source]
        return result

    @classmethod
    def _request(cls, host: str, port: int, packet: bytes) -> dict[str, Any] | None:
        deadline = time.monotonic() + 4
        with open_socket(host, port) as sock:
            sock.sendall(packet)
            header = recv_exact(sock, 16, deadline)
            length, _, _, opcode = struct.unpack("<iiii", header)
            if length < 16 or length > 1024 * 1024:
                raise ValueError("invalid MongoDB message length")
            body = recv_exact(sock, length - 16, deadline)
        if opcode == 2013:
            if len(body) < 5 or struct.unpack_from("<I", body)[0] != 0 or body[4] != 0:
                return None
            return _parse_bson(body[5:])
        if opcode == 1 and len(body) >= 20:
            count = struct.unpack_from("<i", body, 16)[0]
            if count > 0:
                return _parse_bson(body[20:])
        return None


def _parse_bson(payload: bytes) -> dict[str, Any]:
    if len(payload) < 5:
        raise ValueError("truncated BSON document")
    length = struct.unpack_from("<i", payload)[0]
    if length < 5 or length > len(payload):
        raise ValueError("invalid BSON document length")
    offset, result = 4, {}
    while offset < length - 1:
        kind = payload[offset]
        offset += 1
        end = payload.find(b"\0", offset)
        if end < 0:
            raise ValueError("invalid BSON key")
        key = payload[offset:end].decode(errors="replace")
        offset = end + 1
        if kind == 0x10:
            result[key] = struct.unpack_from("<i", payload, offset)[0]
            offset += 4
        elif kind == 0x12:
            result[key] = struct.unpack_from("<q", payload, offset)[0]
            offset += 8
        elif kind == 0x08:
            result[key] = payload[offset] != 0
            offset += 1
        elif kind == 0x02:
            size = struct.unpack_from("<i", payload, offset)[0]
            offset += 4
            result[key] = payload[offset : offset + max(0, size - 1)].decode(
                errors="replace"
            )
            offset += size
        elif kind == 0x01:
            offset += 8
        elif kind in (0x09, 0x11):
            result[key] = struct.unpack_from("<q", payload, offset)[0]
            offset += 8
        elif kind == 0x05:
            size = struct.unpack_from("<i", payload, offset)[0]
            offset += 4
            if size < 0 or offset + 1 + size > length:
                raise ValueError("invalid BSON binary value")
            result[key] = payload[offset + 1 : offset + 1 + size].hex()
            offset += 1 + size
        elif kind == 0x07:
            result[key] = payload[offset : offset + 12].hex()
            offset += 12
        elif kind == 0x0A:
            result[key] = None
        elif kind == 0x0B:
            pattern_end = payload.find(b"\0", offset)
            if pattern_end < 0:
                raise ValueError("invalid BSON regex")
            flags_end = payload.find(b"\0", pattern_end + 1)
            if flags_end < 0:
                raise ValueError("invalid BSON regex flags")
            result[key] = payload[offset:flags_end].decode(errors="replace")
            offset = flags_end + 1
        elif kind in (0x03, 0x04):
            nested_size = struct.unpack_from("<i", payload, offset)[0]
            nested = _parse_bson(payload[offset : offset + nested_size])
            result[key] = nested
            offset += nested_size
        else:
            raise ValueError(f"unsupported BSON type 0x{kind:02x}")
    return result


MongoDBEnum.parse_bson = staticmethod(_parse_bson)
