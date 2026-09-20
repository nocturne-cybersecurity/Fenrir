"""Detector pasivo de cabeceras de seguridad HTTP ausentes."""
from __future__ import annotations

from typing import ClassVar

from fenrir.core.state import Finding, FindingStatus, NodeType, StateGraph
from fenrir.interfaces.findings import FindingDetector, FindingValidator


class MissingSecurityHeaders(FindingDetector):
    name = "missing_security_headers_detector"
    requires: ClassVar[list[NodeType]] = [NodeType.SERVICE]
    priority = 45

    def can_run(self, state: StateGraph) -> bool:
        return any(
            self._is_http(service)
            and isinstance(service.data.get("headers"), dict)
            and not self._already_detected(service, state)
            for service in state.find(NodeType.SERVICE)
        )

    def detect(self, state: StateGraph) -> list[Finding]:
        findings: list[Finding] = []
        for service in state.find(NodeType.SERVICE):
            if not self._is_http(service) or not isinstance(service.data.get("headers"), dict):
                continue
            if self._already_detected(service, state):
                continue
            headers = {str(key).lower() for key in service.data["headers"]}
            missing = sorted({"content-security-policy", "x-content-type-options"} - headers)
            if not missing:
                continue
            host = self._host_of(service, state)
            if not host:
                continue
            findings.append(
                Finding(
                    target=host,
                    service=service.id,
                    title="Missing HTTP security headers",
                    severity="low",
                    confidence=0.82,
                    evidence=[{"service": service.id, "missing_headers": missing}],
                    references=["OWASP: security headers"],
                )
            )
        return findings

    @staticmethod
    def _already_detected(service, state: StateGraph) -> bool:
        return any(
            finding.data.get("service") == service.id
            and finding.data.get("title") == "Missing HTTP security headers"
            for finding in state.find(NodeType.FINDING)
        )

    @staticmethod
    def _is_http(service) -> bool:
        return (service.data.get("name") or "").lower() in {
            "http", "https", "http-proxy", "http-alt",
        }

    @staticmethod
    def _host_of(service, state: StateGraph) -> str | None:
        for port in state.find(NodeType.PORT, number=service.data.get("port")):
            return port.data.get("host")
        return None


class MissingSecurityHeadersValidator(FindingValidator):
    name = "missing_security_headers_validator"
    priority = 40

    def can_validate(self, finding: Finding) -> bool:
        return finding.title == "Missing HTTP security headers"

    def validate(self, finding: Finding, state: StateGraph) -> FindingStatus:
        return (
            FindingStatus.CONFIRMED
            if finding.evidence and finding.evidence[0].get("missing_headers")
            else FindingStatus.REJECTED
        )
