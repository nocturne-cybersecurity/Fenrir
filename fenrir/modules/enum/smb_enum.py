from __future__ import annotations

import socket

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class SMBEnum(BaseModule):
    name = "smb_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 62

    _SERVICE_NAMES = {"smb", "cifs", "microsoft-ds", "netbios-ssn", "samba"}

    def can_run(self, state: StateGraph) -> bool:
        smb_services = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if (svc.data.get("name") or "").lower() in self._SERVICE_NAMES
            and "smb_banner" not in svc.data
        ]
        return bool(smb_services)

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if (svc.data.get("name") or "").lower() in self._SERVICE_NAMES
            and "smb_banner" not in svc.data
        ]

        found = 0
        for svc in targets:
            host = self._host_of(svc, state)
            if not host:
                continue
            banner = self._grab(host, int(svc.data.get("port", 0)))
            if not banner:
                continue
            svc.data["smb_banner"] = banner
            parsed = self._parse_banner(banner)
            if parsed:
                svc.data.update(parsed)
            found += 1

        return ModuleResult(True, found, f"{found} servicios SMB enumerados")

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
                data = sock.recv(4096)
                if not data:
                    return None
                return data.decode("latin-1", errors="ignore").strip()
        except (OSError, socket.timeout, ValueError):
            return None

    @staticmethod
    def _parse_banner(banner: str) -> dict[str, str]:
        payload = banner.encode("latin-1", errors="ignore")
        if payload.startswith(b"\xffSMB"):
            return {
                "smb_magic": "SMB",
                "smb_negotiation": payload[:64].hex(),
            }
        if payload:
            return {"smb_banner": banner[:256]}
        return {}
