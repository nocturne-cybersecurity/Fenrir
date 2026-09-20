"""Recon: escaneo de puertos y servicios con Nmap."""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class NmapScan(BaseModule):
    name = "nmap_scan"
    phase = "recon"
    requires = [NodeType.TARGET]
    produces = [NodeType.HOST, NodeType.PORT, NodeType.SERVICE]
    priority = 100

    def can_run(self, state: StateGraph) -> bool:
        # Solo si hay targets y aún no hemos enumerado hosts
        return bool(state.find(NodeType.TARGET)) and not state.find(NodeType.HOST)

    def run(self, state: StateGraph) -> ModuleResult:
        if not shutil.which("nmap"):
            return ModuleResult(False, message="nmap no está instalado")

        targets = [n.id for n in state.find(NodeType.TARGET)]
        added = 0
        for target in targets:
            xml = self._scan(target)
            if not xml:
                continue
            added += self._parse(xml, target, state)
        return ModuleResult(True, added, f"{added} nodos añadidos")

    def _scan(self, target: str) -> str:
        try:
            proc = subprocess.run(
                ["nmap", "-sV", "-T4", "-oX", "-", target],
                capture_output=True,
                text=True,
                timeout=600,
            )
            return proc.stdout
        except subprocess.TimeoutExpired:
            return ""

    def _parse(self, xml: str, target: str, state: StateGraph) -> int:
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return 0

        count = 0
        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            addr = addr_el.get("addr")
            if not addr:
                continue

            state.add_node(Node(NodeType.HOST, addr, {"ip": addr}))
            state.add_edge(target, addr, "resolves_to")
            count += 1

            for port in host.findall(".//port"):
                pnum = port.get("portid")
                proto = port.get("protocol", "tcp")
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_id = f"{addr}:{pnum}/{proto}"
                svc_el = port.find("service")
                svc_name = svc_el.get("name") if svc_el is not None else "unknown"
                svc_product = svc_el.get("product") if svc_el is not None else None
                svc_version = svc_el.get("version") if svc_el is not None else None

                state.add_node(
                    Node(NodeType.PORT, port_id,
                         {"number": int(pnum), "protocol": proto, "host": addr})
                )
                state.add_node(
                    Node(NodeType.SERVICE, f"{port_id}:{svc_name}",
                         {"name": svc_name, "port": int(pnum),
                          "product": svc_product, "version": svc_version})
                )
                state.add_edge(addr, port_id, "has_port")
                count += 2
        return count