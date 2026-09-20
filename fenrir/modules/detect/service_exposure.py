"""Detección y validación pasiva de exposición de servicios no HTTP."""
from __future__ import annotations

from typing import ClassVar

from fenrir.core.state import Finding, FindingStatus, NodeType, StateGraph
from fenrir.interfaces.findings import FindingDetector, FindingValidator


class ServiceExposureDetector(FindingDetector):
    """Convierte fingerprints de protocolos en findings trazables."""

    name = "service_exposure_detector"
    requires: ClassVar[list[NodeType]] = [NodeType.SERVICE]
    priority = 44

    _EVIDENCE_KEYS: ClassVar[dict[str, tuple[str, ...]]] = {
        "ftp": ("ftp_banner",),
        "ldap": ("ldap_response", "ldap_anonymous_bind"),
        "memcached": ("memcached_version", "memcached_banner"),
        "mongodb": ("mongodb_response", "mongodb_server_version"),
        "mysql": ("mysql_server_version",),
        "mariadb": ("mysql_server_version",),
        "postgresql": ("postgresql_server_version",),
        "redis": ("redis_ping", "redis_server_version"),
        "smb": ("smb_banner", "smb_magic"),
        "ssh": ("banner",),
    }

    def can_run(self, state: StateGraph) -> bool:
        return any(
            self._evidence_for(service)
            and not self._already_detected(service, state)
            for service in state.find(NodeType.SERVICE)
        )

    def detect(self, state: StateGraph) -> list[Finding]:
        findings: list[Finding] = []
        for service in state.find(NodeType.SERVICE):
            evidence = self._evidence_for(service)
            if not evidence or self._already_detected(service, state):
                continue
            host = self._host_of(service, state)
            if not host:
                continue
            findings.append(
                Finding(
                    target=host,
                    service=service.id,
                    title="Network service exposes protocol metadata",
                    severity="info",
                    confidence=0.76,
                    evidence=[{
                        "service": service.data.get("name"),
                        "port": service.data.get("port"),
                        "metadata": evidence,
                    }],
                    references=["CWE-200"],
                )
            )
        return findings

    @classmethod
    def _evidence_for(cls, service) -> dict[str, object]:
        name = str(service.data.get("name") or "").lower()
        keys = next(
            (values for family, values in cls._EVIDENCE_KEYS.items() if family in name),
            (),
        )
        return {key: service.data[key] for key in keys if key in service.data}

    @staticmethod
    def _already_detected(service, state: StateGraph) -> bool:
        return any(
            finding.data.get("service") == service.id
            and finding.data.get("title") == "Network service exposes protocol metadata"
            for finding in state.find(NodeType.FINDING)
        )

    @staticmethod
    def _host_of(service, state: StateGraph) -> str | None:
        for port in state.find(NodeType.PORT, number=service.data.get("port")):
            return port.data.get("host")
        return None


class ServiceExposureValidator(FindingValidator):
    name = "service_exposure_validator"
    priority = 39

    def can_validate(self, finding: Finding) -> bool:
        return finding.title == "Network service exposes protocol metadata"

    def validate(self, finding: Finding, state: StateGraph) -> FindingStatus:
        service_id = finding.service
        service = state.get(service_id) if service_id else None
        if service is None:
            return FindingStatus.REJECTED
        return (
            FindingStatus.CONFIRMED
            if ServiceExposureDetector._evidence_for(service)
            else FindingStatus.REJECTED
        )
