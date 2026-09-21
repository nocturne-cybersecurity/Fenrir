"""NVD (National Vulnerability Database) API client for CVE lookup."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class CVSSScore:
    """CVSS score information."""
    version: str
    base_score: float
    severity: str


@dataclass
class CVEDetail:
    """Detailed CVE information from NVD."""
    cve_id: str
    description: str
    published: str
    modified: str
    severity: str
    cvss_score: CVSSScore | None
    references: list[str]
    affected_products: list[str]


class NVDClient:
    """Client for NIST NVD API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6.0  # NVD allows ~10 requests per rolling 60-second window

    def __init__(self, api_key: str | None = None) -> None:
        """Initialize NVD client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits.
                    Get one at: https://nvd.nist.gov/developers/request-an-api-key
        """
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})

    def _make_request(self, params: dict[str, Any]) -> dict[str, Any]:
        """Make a request to NVD API with rate limiting."""
        time.sleep(self.RATE_LIMIT_DELAY)
        
        response = self.session.get(self.BASE_URL, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_cve(self, cve_id: str) -> CVEDetail | None:
        """Get detailed information for a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")
            
        Returns:
            CVEDetail if found, None otherwise
        """
        try:
            params = {"cveId": cve_id}
            data = self._make_request(params)
            
            if not data.get("vulnerabilities"):
                return None
            
            vuln_data = data["vulnerabilities"][0]["cve"]
            return self._parse_cve(vuln_data)
        except (requests.RequestException, KeyError, ValueError) as e:
            print(f"  Error fetching CVE {cve_id}: {e}")
            return None

    def search_cves(
        self,
        keyword: str | None = None,
        cpe_name: str | None = None,
        cvss_severity: str | None = None,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> list[CVEDetail]:
        """Search for CVEs matching criteria.
        
        Args:
            keyword: Search keyword
            cpe_name: CPE (Common Platform Enumeration) name
            cvss_severity: Filter by CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)
            results_per_page: Number of results per page (max 2000)
            start_index: Starting index for pagination
            
        Returns:
            List of CVE details
        """
        try:
            params = {
                "resultsPerPage": min(results_per_page, 2000),
                "startIndex": start_index,
            }
            
            if keyword:
                params["keywordSearch"] = keyword
            if cpe_name:
                params["cpeName"] = cpe_name
            if cvss_severity:
                params["cvssV3Severity"] = cvss_severity.upper()
            
            data = self._make_request(params)
            
            cves = []
            for item in data.get("vulnerabilities", []):
                cves.append(self._parse_cve(item["cve"]))
            
            return cves
        except (requests.RequestException, KeyError, ValueError) as e:
            print(f"  Error searching CVEs: {e}")
            return []

    def search_by_product(
        self,
        vendor: str,
        product: str,
        version: str | None = None,
    ) -> list[CVEDetail]:
        """Search for CVEs affecting a specific product.
        
        Args:
            vendor: Vendor name (e.g., "apache")
            product: Product name (e.g., "httpd")
            version: Optional version string
            
        Returns:
            List of CVE details
        """
        cpe_name = f"cpe:2.3:a:{vendor}:{product}"
        if version:
            cpe_name += f":{version}"
        
        return self.search_cves(cpe_name=cpe_name)

    def _parse_cve(self, vuln_data: dict[str, Any]) -> CVEDetail:
        """Parse CVE data from NVD API response."""
        cve_id = vuln_data["id"]
        
        # Description
        descriptions = vuln_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Dates
        published = vuln_data.get("published", "")
        modified = vuln_data.get("lastModified", "")
        
        # CVSS score
        cvss_score = None
        metrics = vuln_data.get("metrics", {})
        
        # Try CVSS v3.1 first
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = CVSSScore(
                version="3.1",
                base_score=cvss_data.get("baseScore", 0.0),
                severity=cvss_data.get("baseSeverity", "UNKNOWN"),
            )
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = CVSSScore(
                version="3.0",
                base_score=cvss_data.get("baseScore", 0.0),
                severity=cvss_data.get("baseSeverity", "UNKNOWN"),
            )
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = CVSSScore(
                version="2.0",
                base_score=cvss_data.get("baseScore", 0.0),
                severity=cvss_data.get("baseSeverity", "UNKNOWN"),
            )
        
        severity = cvss_score.severity if cvss_score else "UNKNOWN"
        
        # References
        references = []
        for ref in vuln_data.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)
        
        # Affected products (CPEs)
        affected_products = []
        for config in vuln_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    cpe_str = cpe.get("criteria", "")
                    if cpe_str:
                        affected_products.append(cpe_str)
        
        return CVEDetail(
            cve_id=cve_id,
            description=description,
            published=published,
            modified=modified,
            severity=severity,
            cvss_score=cvss_score,
            references=references,
            affected_products=affected_products,
        )
