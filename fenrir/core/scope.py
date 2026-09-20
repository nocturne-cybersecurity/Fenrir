"""Scope guard: evita que el framework toque hosts fuera del alcance."""
from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml


class ScopeError(Exception):
    pass


class Scope:
    """Whitelist de targets permitidos.

    Acepta:
      - IPs exactas: 10.10.10.5
      - CIDRs: 10.10.10.0/24
      - Dominios: scanme.nmap.org
      - Wildcards: *.midominio.com
    """

    def __init__(self, allowed: list[str]) -> None:
        self.networks: list[ipaddress._BaseNetwork] = []
        self.domains: list[str] = []
        self.wildcards: list[str] = []
        for entry in allowed:
            self._add(entry)

    def _add(self, entry: str) -> None:
        entry = entry.strip()
        if not entry:
            return
        try:
            self.networks.append(ipaddress.ip_network(entry, strict=False))
            return
        except ValueError:
            pass
        if entry.startswith("*."):
            self.wildcards.append(entry[2:].lower())
        else:
            self.domains.append(entry.lower())

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text())
        return cls(data.get("allowed", []))

    def is_allowed(self, target: str) -> bool:
        # IP
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in net for net in self.networks)
        except ValueError:
            pass
        # Dominio
        t = target.lower()
        if t in self.domains:
            return True
        return any(t == w or t.endswith("." + w) for w in self.wildcards)

    def assert_allowed(self, target: str) -> None:
        if not self.is_allowed(target):
            raise ScopeError(
                f"Target '{target}' fuera de alcance. "
                f"Añádelo a config/scope.yaml si tienes autorización."
            )