"""Small helpers shared by passive protocol enumeration modules."""

from __future__ import annotations

import socket
import time
from typing import Any

from fenrir.core.state import Node, NodeType, StateGraph

MAX_READ = 256 * 1024


def service_host(service: Node, state: StateGraph) -> str | None:
    """Resolve a service to its port's host without assuming one host."""
    if service.data.get("host"):
        return str(service.data["host"])
    try:
        number = int(service.data.get("port", 0))
    except (TypeError, ValueError):
        return None

    candidates = state.find(NodeType.PORT, number=number)
    for port in candidates:
        if f":{number}/" in port.id and port.data.get("host"):
            return str(port.data["host"])
    if len(candidates) == 1:
        return str(candidates[0].data.get("host") or "") or None
    return None


def service_port(service: Node) -> int | None:
    try:
        port = int(service.data.get("port", 0))
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def is_tcp_service(service: Node, state: StateGraph) -> bool:
    protocol = str(service.data.get("protocol") or "").lower()
    if protocol:
        return protocol == "tcp"
    port = service_port(service)
    if port is None:
        return False
    candidates = state.find(NodeType.PORT, number=port)
    return not candidates or any(
        str(node.data.get("protocol", "tcp")).lower() == "tcp" for node in candidates
    )


def mark_attempt(service: Node, marker: str, error: str | None = None) -> None:
    """Make an attempt terminal for this run, including failed connections."""
    service.data[f"{marker}_attempted"] = True
    service.data[f"{marker}_checked"] = True
    if error:
        service.data[f"{marker}_error"] = error[:200]


def open_socket(host: str, port: int, timeout: float = 3.0) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def recv_exact(
    sock: socket.socket, size: int, deadline: float, limit: int = MAX_READ
) -> bytes:
    if size < 0 or size > limit:
        raise ValueError("invalid protocol frame size")
    result = bytearray()
    while len(result) < size:
        if time.monotonic() >= deadline:
            raise TimeoutError("protocol read timed out")
        chunk = sock.recv(min(size - len(result), 8192))
        if not chunk:
            raise ConnectionError("peer closed connection")
        result.extend(chunk)
    return bytes(result)


def recv_line(sock: socket.socket, deadline: float, limit: int = 8192) -> bytes:
    result = bytearray()
    while len(result) < limit:
        if time.monotonic() >= deadline:
            raise TimeoutError("protocol line timed out")
        chunk = sock.recv(1)
        if not chunk:
            break
        result.extend(chunk)
        if result.endswith(b"\n"):
            return bytes(result)
    return bytes(result)


def bounded_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


def compact_metadata(value: Any) -> Any:
    """Keep data written to the graph bounded and JSON-friendly."""
    if isinstance(value, bytes):
        return value[:256].hex()
    if isinstance(value, str):
        return value[:512]
    if isinstance(value, dict):
        return {str(k): compact_metadata(v) for k, v in list(value.items())[:64]}
    if isinstance(value, list):
        return [compact_metadata(v) for v in value[:64]]
    return value
