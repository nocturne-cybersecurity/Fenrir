"""Enum: extrae banner SSH para identificar versión."""
from __future__ import annotations

import socket

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class SSHBanner(BaseModule):
    name = "ssh_banner"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 60

    def can_run(self, state: StateGraph) -> bool:
        ssh_svcs = [
            s for s in state.find(NodeType.SERVICE)
            if s.data.get("name") == "ssh" and "banner" not in s.data
        ]
        return bool(ssh_svcs)

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            s for s in state.find(NodeType.SERVICE)
            if s.data.get("name") == "ssh" and "banner" not in s.data
        ]
        found = 0
        for svc in targets:
            host = self._host_of(svc, state)
            if not host:
                continue
            banner = self._grab(host, svc.data["port"])
            if banner:
                svc.data["banner"] = banner
                found += 1
        return ModuleResult(True, found, f"{found} banners SSH capturados")

    def _host_of(self, svc: Node, state: StateGraph) -> str | None:
        port_num = svc.data.get("port")
        for p in state.find(NodeType.PORT, number=port_num):
            return p.data.get("host")
        return None

    def _grab(self, host: str, port: int) -> str | None:
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                return s.recv(256).decode("utf-8", errors="ignore").strip()
        except (OSError, socket.timeout):
            return None