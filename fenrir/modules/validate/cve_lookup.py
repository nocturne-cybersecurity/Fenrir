"""CVE lookup module using external APIs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult
from fenrir.knowledge.nvd_client import CVEDetail, NVDClient
from fenrir.knowledge.trident_client import CVEDetailEnriched, TridentStackClient


@dataclass
class CVELookupConfig:
    """Configuration for CVE lookup."""
    use_nvd: bool = True
    use_trident: bool = True
    nvd_api_key: str | None = None


class CVELookupModule(BaseModule):
    """Module for automatic CVE lookup using external APIs."""

    name: str = "cve_lookup"
    phase: str = "validation"
    requires: list[NodeType] = [NodeType.FINDING]
    produces: list[NodeType] = [NodeType.VULN]
    priority: int = 15

    def __init__(self, config: CVELookupConfig | None = None) -> None:
        """Initialize CVE lookup module.
        
        Args:
            config: Configuration for API clients
        """
        self.config = config or CVELookupConfig()
        
        self.nvd_client = NVDClient(api_key=self.config.nvd_api_key) if self.config.use_nvd else None
        self.trident_client = TridentStackClient() if self.config.use_trident else None

    def can_run(self, state: StateGraph) -> bool:
        """Run if there are findings to validate."""
        return len(state.find(NodeType.FINDING)) > 0

    def run(self, state: StateGraph) -> ModuleResult:
        """Look up CVEs for findings and enrich vulnerability data."""
        added = 0
        
        for finding_node in state.find(NodeType.FINDING):
            finding_data = finding_node.data
            
            # Skip if already validated
            if finding_data.get("status") == "confirmed":
                continue
            
            # Extract product and version
            product = finding_data.get("product")
            version = finding_data.get("version")
            
            if not product:
                continue
            
            # Search for CVEs
            cves = self._search_cves(product, version)
            
            if not cves:
                continue
            
            # Add CVEs to state
            for cve in cves:
                # Check if already exists
                existing = state.find(NodeType.VULN, id=cve.cve_id)
                if existing:
                    continue
                
                # Add vulnerability node
                vuln_data = {
                    "id": cve.cve_id,
                    "name": cve.cve_id,
                    "description": cve.description,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score.base_score if cve.cvss_score else 0.0,
                    "cvss_severity": cve.cvss_score.severity if cve.cvss_score else "UNKNOWN",
                    "published": cve.published,
                    "modified": cve.modified,
                    "references": cve.references,
                    "affected_products": cve.affected_products,
                }
                
                state.add_knowledge_node(NodeType.VULN, vuln_data, cve.cve_id)
                state.add_edge(finding_node.id, cve.cve_id, "has_cve")
                added += 1
            
            # Confirm finding if CVEs found
            finding_data["status"] = "confirmed"
            finding_data["cves"] = [cve.cve_id for cve in cves]
        
        return ModuleResult(
            success=added > 0,
            added_nodes=added,
            message=f"Looked up {added} CVEs",
        )

    def _search_cves(self, product: str, version: str | None = None) -> list[CVEDetail]:
        """Search for CVEs affecting a product.
        
        Args:
            product: Product name
            version: Optional version
            
        Returns:
            List of CVE details
        """
        cves = []
        
        # Try NVD first
        if self.nvd_client:
            vendor = self._extract_vendor(product)
            cves.extend(self.nvd_client.search_by_product(vendor, product, version))
        
        # Try TridentStack for enriched data
        if self.trident_client:
            enriched = self.trident_client.search_cves(query=f"{product} {version or ''}")
            # Convert to CVEDetail format
            for e in enriched:
                cves.append(self._enriched_to_detail(e))
        
        return cves

    def _extract_vendor(self, product: str) -> str:
        """Extract vendor from product name."""
        # Simple heuristic: first word before space or common vendor mapping
        vendor_map = {
            "apache": "apache",
            "nginx": "nginx",
            "openssh": "openbsd",
            "microsoft": "microsoft",
            "openssl": "openssl",
        }
        
        product_lower = product.lower()
        for vendor_name, vendor_id in vendor_map.items():
            if vendor_name in product_lower:
                return vendor_id
        
        # Default: first word
        return product.split()[0].lower()

    def _enriched_to_detail(self, enriched: CVEDetailEnriched) -> CVEDetail:
        """Convert TridentStack enriched data to CVEDetail."""
        from fenrir.knowledge.nvd_client import CVSSScore
        
        cvss_score = None
        if enriched.cvss:
            cvss_score = CVSSScore(
                version=enriched.cvss.get("version", "3.1"),
                base_score=enriched.cvss.get("baseScore", 0.0),
                severity=enriched.severity,
            )
        
        return CVEDetail(
            cve_id=enriched.cve_id,
            description="",
            published="",
            modified="",
            severity=enriched.severity,
            cvss_score=cvss_score,
            references=[r.get("url", "") for r in enriched.references],
            affected_products=[],
        )
