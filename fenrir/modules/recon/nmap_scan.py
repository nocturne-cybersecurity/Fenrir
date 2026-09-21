"""Recon: escaneo de puertos y servicios con Nmap."""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml
from yaml import YAMLError

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult


class NmapScan(BaseModule):
    name = "nmap_scan"
    phase = "recon"
    requires = [NodeType.TARGET]
    produces = [NodeType.HOST, NodeType.PORT, NodeType.SERVICE]
    priority = 100

    def __init__(self):
        super().__init__()
        self.config = self._load_config()

    def _load_config(self) -> dict:
        config_path = Path(__file__).parent.parent.parent / "config" / "nmap.yaml"
        default_config = {
            "default_options": ["-sV", "-sC", "-T4", "-Pn", "-oX", "-"],
            "vuln_scripts": False,
            "timeout": 600
        }
        if config_path.exists():
            try:
                with open(config_path) as f:
                    return yaml.safe_load(f) or default_config
            except (OSError, YAMLError):
                return default_config
        return default_config

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
            options = self.config.get("default_options", ["-sV", "-T4", "-Pn", "-oX", "-"])
            timeout = self.config.get("timeout", 600)
            cmd = ["nmap"] + options
            
            # Add vuln scripts if enabled in config
            if self.config.get("vuln_scripts", False):
                cmd.append("--script=vuln")
            
            ports = self.config.get("ports")
            if ports and "-p" not in options:
                cmd.extend(["-p", str(ports)])
            cmd.append(target)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
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