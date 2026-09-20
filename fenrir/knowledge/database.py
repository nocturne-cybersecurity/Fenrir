from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from fenrir.models.exploit import Exploit
from fenrir.models.vulnerability import Vulnerability


class KnowledgeDatabase:
    """Catálogo local cargado desde archivos JSON, sin consultas de red."""

    def __init__(self, data_dir: str | Path = "data") -> None:
        self.data_dir = Path(data_dir)
        self.vulnerabilities = self._load_vulnerabilities()
        self.exploits = self._load_exploits()

    def match(self, product: str, version: str) -> list[Vulnerability]:
        return [
            vulnerability
            for vulnerability in self.vulnerabilities
            if vulnerability.matches(product, version)
        ]

    def exploits_for(self, vulnerability_id: str) -> list[Exploit]:
        return [
            exploit
            for exploit in self.exploits
            if vulnerability_id in exploit.vulnerability_ids
        ]

    def _load_vulnerabilities(self) -> list[Vulnerability]:
        records = self._load_json("vulnerabilities.json")
        return [Vulnerability(**record) for record in records]

    def _load_exploits(self) -> list[Exploit]:
        records = self._load_json("exploits.json")
        return [Exploit(**record) for record in records]

    def _load_json(self, filename: str) -> list[dict]:
        path = self.data_dir / filename
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as stream:
            payload = json.load(stream)
        if not isinstance(payload, list):
            raise TypeError(f"{path} must contain a JSON list")
        return list(payload)

    @classmethod
    def from_records(
        cls,
        vulnerabilities: Iterable[Vulnerability],
        exploits: Iterable[Exploit] = (),
    ) -> KnowledgeDatabase:
        instance = cls.__new__(cls)
        instance.data_dir = Path()
        instance.vulnerabilities = list(vulnerabilities)
        instance.exploits = list(exploits)
        return instance
