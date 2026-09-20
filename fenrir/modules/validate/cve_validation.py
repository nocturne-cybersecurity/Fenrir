"""Validación local de findings asociados a CVEs."""
from __future__ import annotations

from fenrir.core.state import Finding, FindingStatus, Node, NodeType, StateGraph
from fenrir.interfaces.findings import FindingValidator
from fenrir.knowledge.database import KnowledgeDatabase


class CVEValidator(FindingValidator):
    name = "cve_validator"
    phase = "validation"
    priority = 38

    def __init__(self, database: KnowledgeDatabase | None = None) -> None:
        self.database = database or KnowledgeDatabase()

    def can_validate(self, finding: Finding) -> bool:
        return any(reference.startswith("CVE-") for reference in finding.references)

    def validate(self, finding: Finding, state: StateGraph) -> FindingStatus:
        service = state.get(finding.service) if finding.service else None
        if service is None:
            return FindingStatus.REJECTED
        product = service.data.get("product") or service.data.get("name")
        version = service.data.get("version")
        if not product or not version:
            return FindingStatus.REJECTED
        matched_vulns = self.database.match(str(product), str(version))
        matched_ids = {vulnerability.id for vulnerability in matched_vulns}
        
        status = (
            FindingStatus.CONFIRMED
            if matched_ids.intersection(finding.references)
            else FindingStatus.REJECTED
        )
        
        # Si se confirma, añadir vulnerabilidades al estado
        if status == FindingStatus.CONFIRMED:
            for vuln in matched_vulns:
                if vuln.id in finding.references:
                    # Verificar si ya existe
                    existing = state.find(NodeType.VULN, id=vuln.id)
                    if not existing:
                        state.add_knowledge_node(NodeType.VULN, vuln, vuln.id)
                        if service:
                            state.add_edge(service.id, vuln.id, "has_vulnerability")
        
        return status
