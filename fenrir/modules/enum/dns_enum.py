from __future__ import annotations

import shutil
import socket
import subprocess

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class DNSEnum(BaseModule):
    name = "dns_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 58

    _SERVICE_NAMES = {"dns", "domain", "domain-s", "dns-over-udp", "dns-over-tcp"}

    def can_run(self, state: StateGraph) -> bool:
        dns_services = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if (svc.data.get("name") or "").lower() in self._SERVICE_NAMES
            and "dns_records" not in svc.data
        ]
        return bool(dns_services)

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if (svc.data.get("name") or "").lower() in self._SERVICE_NAMES
            and "dns_records" not in svc.data
        ]

        found = 0
        for svc in targets:
            host = self._host_of(svc, state)
            if not host:
                continue
            records = self._resolve_records(host)
            if not records:
                continue
            svc.data["dns_records"] = records
            found += 1

        return ModuleResult(True, found, f"{found} servicios DNS enumerados")

    def _host_of(self, svc: Node, state: StateGraph) -> str | None:
        port_num = svc.data.get("port")
        for port in state.find(NodeType.PORT, number=port_num):
            return port.data.get("host")
        return None

    @staticmethod
    def _parse_getent(output: str) -> list[str]:
        values: list[str] = []
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            if ip not in values:
                values.append(ip)
        return values

    def _resolve_records(self, host: str) -> dict[str, list[str]]:
        records: dict[str, list[str]] = {}
        getent = shutil.which("getent")

        if getent:
            for family, arg in (("A", "ahostsv4"), ("AAAA", "ahostsv6")):
                try:
                    completed = subprocess.run(
                        [getent, arg, host],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                except (OSError, subprocess.SubprocessError):
                    continue
                if completed.returncode == 0 and completed.stdout.strip():
                    values = self._parse_getent(completed.stdout)
                    if values:
                        records.setdefault(family, []).extend(values)

        if records:
            for key, value in list(records.items()):
                records[key] = list(dict.fromkeys(value))
            return records

        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return {}

        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                records.setdefault("A", []).append(sockaddr[0])
            elif family == socket.AF_INET6:
                records.setdefault("AAAA", []).append(sockaddr[0])

        for key, value in list(records.items()):
            records[key] = list(dict.fromkeys(value))
        return records
