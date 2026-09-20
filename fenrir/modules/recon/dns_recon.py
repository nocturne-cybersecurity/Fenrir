from __future__ import annotations

import shutil
import socket
import subprocess

from fenrir.core.state import NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class DNSRecon(BaseModule):
    name = "dns_recon"
    phase = "recon"
    requires = [NodeType.TARGET]
    produces = [NodeType.HOST]
    priority = 90

    def can_run(self, state: StateGraph) -> bool:
        for target in state.find(NodeType.TARGET):
            if target.data.get("dns_records") is not None:
                continue
            if self._is_name(target.id):
                return True
        for host in state.find(NodeType.HOST):
            if host.data.get("hostname") and host.data.get("dns_records") is None:
                return True
        return False

    def run(self, state: StateGraph) -> ModuleResult:
        collected = 0
        for target in state.find(NodeType.TARGET):
            name = target.data.get("hostname") or target.id
            if not self._is_name(name):
                continue
            records = {}
            a_records = self._lookup(name, "A")
            if a_records:
                records["A"] = a_records
            aaaa_records = self._lookup(name, "AAAA")
            if aaaa_records:
                records["AAAA"] = aaaa_records
            if not records:
                continue
            target.data["dns_records"] = records
            collected += 1

        for host in state.find(NodeType.HOST):
            name = host.data.get("hostname") or host.id
            if not self._is_name(name):
                continue
            if host.data.get("dns_records") is not None:
                continue
            records = {}
            a_records = self._lookup(name, "A")
            if a_records:
                records["A"] = a_records
            aaaa_records = self._lookup(name, "AAAA")
            if aaaa_records:
                records["AAAA"] = aaaa_records
            if not records:
                continue
            host.data["dns_records"] = records
            collected += 1

        return ModuleResult(
            success=bool(collected),
            added_nodes=collected,
            message=f"{collected} registros DNS recopilados" if collected else "No se pudo resolver DNS",
        )

    @staticmethod
    def _is_name(value: str) -> bool:
        if not value:
            return False
        if value.startswith("[") and value.endswith("]"):
            return False
        try:
            import ipaddress

            ipaddress.ip_address(value)
            return False
        except ValueError:
            return True

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

    def _lookup(self, name: str, family: str) -> list[str]:
        if not name:
            return []

        getent = shutil.which("getent")
        if getent:
            arg = "ahostsv4" if family == "A" else "ahostsv6"
            try:
                completed = subprocess.run(
                    [getent, arg, name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                completed = None
            if completed and completed.returncode == 0 and completed.stdout.strip():
                values = self._parse_getent(completed.stdout)
                if values:
                    return values

        try:
            infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []

        values: list[str] = []
        for family_info, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if family_info == socket.AF_INET6 and family == "AAAA":
                if ip not in values:
                    values.append(ip)
            elif family_info == socket.AF_INET and family == "A":
                if ip not in values:
                    values.append(ip)
        return values
