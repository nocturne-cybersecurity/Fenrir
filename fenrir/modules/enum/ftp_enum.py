from __future__ import annotations

import re
import socket

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class FTPEnum(BaseModule):
    name = "ftp_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 60

    _SERVICE_NAMES = {"ftp", "ftp-data", "ftp-control", "ftps"}

    def can_run(self, state: StateGraph) -> bool:
        ftp_services = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if (svc.data.get("name") or "").lower().startswith("ftp")
            and "ftp_banner" not in svc.data
        ]
        return bool(ftp_services)

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if (svc.data.get("name") or "").lower().startswith("ftp")
            and "ftp_banner" not in svc.data
        ]

        found = 0
        for svc in targets:
            host = self._host_of(svc, state)
            if not host:
                continue
            banner = self._grab(host, int(svc.data.get("port", 0)))
            if not banner:
                continue
            svc.data["ftp_banner"] = banner
            parsed = self._parse_banner(banner)
            if parsed:
                svc.data.update(parsed)
            found += 1

        return ModuleResult(True, found, f"{found} servicios FTP enumerados")

    def _host_of(self, svc: Node, state: StateGraph) -> str | None:
        port_num = svc.data.get("port")
        for port in state.find(NodeType.PORT, number=port_num):
            return port.data.get("host")
        return None

    @staticmethod
    def _grab(host: str, port: int) -> str | None:
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                sock.settimeout(3)
                banner = sock.recv(4096)
                if not banner:
                    return None
                return banner.decode("utf-8", errors="ignore").strip()
        except (OSError, socket.timeout, ValueError):
            return None

    @staticmethod
    def _parse_banner(banner: str) -> dict[str, str | int]:
        match = re.search(r"(?m)^\s*(\d{3})\s+(.*)$", banner)
        if not match:
            return {"ftp_banner": banner[:256]}
        code, text = match.groups()
        return {"ftp_code": int(code), "ftp_server": text.strip()[:200]}
