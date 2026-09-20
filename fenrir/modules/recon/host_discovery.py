from __future__ import annotations

import ipaddress
import socket

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class HostDiscovery(BaseModule):
    name = "host_discovery"
    phase = "recon"
    requires = [NodeType.TARGET]
    produces = [NodeType.HOST]
    priority = 95

    def can_run(self, state: StateGraph) -> bool:
        for target in state.find(NodeType.TARGET):
            target_name = target.id
            if state.find(NodeType.HOST, ip=target_name) or state.find(NodeType.HOST, hostname=target_name):
                continue
            return True
        return False

    def run(self, state: StateGraph) -> ModuleResult:
        discovered = 0
        for target in state.find(NodeType.TARGET):
            if state.find(NodeType.HOST, ip=target.id) or state.find(NodeType.HOST, hostname=target.id):
                continue

            ips = self._resolve(target.id)
            if not ips:
                continue

            for ip in ips:
                host = state.add_node(Node(NodeType.HOST, ip, {"ip": ip, "hostname": target.id}))
                state.add_edge(target.id, host.id, "resolves_to")
                discovered += 1

            target.data.setdefault("known_hosts", [])
            for value in ips:
                if value not in target.data["known_hosts"]:
                    target.data["known_hosts"].append(value)

        return ModuleResult(
            success=bool(discovered),
            added_nodes=discovered,
            message=f"{discovered} hosts descubiertos" if discovered else "No se descubrieron hosts nuevos",
        )

    @staticmethod
    def _resolve(value: str) -> list[str]:
        candidate = value.strip()
        if not candidate:
            return []

        try:
            return [str(ipaddress.ip_address(candidate))]
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(candidate, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []

        ips: list[str] = []
        for _family, _socktype, _proto, _canonname, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips
