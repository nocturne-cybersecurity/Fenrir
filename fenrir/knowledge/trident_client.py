"""TridentStack API client for enriched CVE data."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class EPSSScore:
    """Exploit Prediction Scoring System data."""
    score: float
    percentile: float


@dataclass
class KEVInfo:
    """CISA Known Exploited Vulnerabilities info."""
    date_added: str
    due_date: str
    ransomware: bool


@dataclass
class RemediationEntry:
    """Remediation information for a product."""
    ecosystem: str
    product: str
    fixed_version: str
    advisory_id: str
    source_url: str
    source: str
    license: str


@dataclass
class CVEDetailEnriched:
    """Enriched CVE information from TridentStack."""
    cve_id: str
    severity: str
    cvss: dict[str, Any]
    epss: EPSSScore | None
    kev: KEVInfo | None
    remediation: dict[str, Any]
    cwes: list[str]
    references: list[dict[str, str]]
    data_sources: list[dict[str, str]]


class TridentStackClient:
    """Client for TridentStack Free CVE API."""

    BASE_URL = "https://tridentstack.com/api/v1"

    def __init__(self) -> None:
        """Initialize TridentStack client (no API key required)."""
        self.session = requests.Session()

    def get_cve(self, cve_id: str) -> CVEDetailEnriched | None:
        """Get enriched information for a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")
            
        Returns:
            CVEDetailEnriched if found, None otherwise
        """
        try:
            response = self.session.get(f"{self.BASE_URL}/cve/{cve_id}", timeout=30)
            response.raise_for_status()
            data = response.json()
            return self._parse_cve(data)
        except (requests.RequestException, KeyError, ValueError) as e:
            print(f"  Error fetching CVE {cve_id} from TridentStack: {e}")
            return None

    def search_cves(
        self,
        query: str | None = None,
        severity: str | None = None,
        kev: bool | None = None,
        has_fix: bool | None = None,
        epss_min: float | None = None,
        year: int | None = None,
        limit: int = 20,
    ) -> list[CVEDetailEnriched]:
        """Search for CVEs with filters.
        
        Args:
            query: Search query
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            kev: Filter by CISA KEV status
            has_fix: Filter by fix availability
            epss_min: Minimum EPSS score
            year: Filter by year
            limit: Number of results (max 100)
            
        Returns:
            List of enriched CVE details
        """
        try:
            params = {"limit": min(limit, 100)}
            
            if query:
                params["q"] = query
            if severity:
                params["severity"] = severity.upper()
            if kev is not None:
                params["kev"] = str(kev).lower()
            if has_fix is not None:
                params["fix"] = str(has_fix).lower()
            if epss_min is not None:
                params["epss_min"] = str(epss_min)
            if year:
                params["year"] = str(year)
            
            response = self.session.get(f"{self.BASE_URL}/cve", params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            cves = []
            for item in data.get("cves", []):
                cves.append(self._parse_cve(item))
            
            return cves
        except (requests.RequestException, KeyError, ValueError) as e:
            print(f"  Error searching CVEs: {e}")
            return []

    def _parse_cve(self, data: dict[str, Any]) -> CVEDetailEnriched:
        """Parse CVE data from TridentStack API response."""
        cve_id = data.get("cveId", "")
        severity = data.get("severity", "UNKNOWN")
        cvss = data.get("cvss", {})
        
        # EPSS
        epss = None
        epss_data = data.get("epss")
        if epss_data:
            epss = EPSSScore(
                score=epss_data.get("score", 0.0),
                percentile=epss_data.get("percentile", 0.0),
            )
        
        # KEV
        kev = None
        kev_data = data.get("kev")
        if kev_data:
            kev = KEVInfo(
                date_added=kev_data.get("dateAdded", ""),
                due_date=kev_data.get("dueDate", ""),
                ransomware=kev_data.get("ransomware", False),
            )
        
        # Remediation
        remediation = data.get("remediation", {})
        
        # CWEs
        cwes = data.get("cwes", [])
        
        # References
        references = []
        for ref in data.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "type": ref.get("type", ""),
            })
        
        # Data sources
        data_sources = []
        for source in data.get("dataSources", []):
            data_sources.append({
                "name": source.get("name", ""),
                "license": source.get("license", ""),
            })
        
        return CVEDetailEnriched(
            cve_id=cve_id,
            severity=severity,
            cvss=cvss,
            epss=epss,
            kev=kev,
            remediation=remediation,
            cwes=cwes,
            references=references,
            data_sources=data_sources,
        )
