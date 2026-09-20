"""Passive reverse-proxy/CDN observations and possible origin candidates.

This module deliberately does not try alternate IPs, alter Host headers, or
query third-party services.  It only uses data already in the graph, a single
low-impact HTTP request when headers are not present, DNS resolution, and the
peer certificate exposed by an HTTPS service.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Iterable, Mapping
from typing import Any, ClassVar

import requests
from urllib3.exceptions import InsecureRequestWarning

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ProxyOriginRecon(BaseModule):
    """Record proxy evidence and *possible*, never confirmed, origin hosts."""

    name = "proxy_origin_recon"
    phase = "recon"
    requires: ClassVar[list[NodeType]] = [NodeType.TARGET]
    produces: ClassVar[list[NodeType]] = [NodeType.HOST]
    priority = 72

    _HTTP_NAMES: ClassVar[set[str]] = {"http", "https", "http-proxy", "http-alt"}
    _MAX_CANDIDATES = 32
    _MAX_EVIDENCE = 12
    _MAX_HEADER_VALUE = 256
    _DNS_TIMEOUT = 3.0
    _HTTP_TIMEOUT = (2.0, 5.0)

    def can_run(self, state: StateGraph) -> bool:
        targets = state.find(NodeType.TARGET)
        if not targets:
            return False
        if any(not target.data.get("proxy_origin_recon_attempted") for target in targets):
            return True
        return any(
            self._is_http_service(service)
            and not service.data.get("proxy_origin_recon_attempted")
            for service in state.find(NodeType.SERVICE)
        )

    def run(self, state: StateGraph) -> ModuleResult:
        targets = state.find(NodeType.TARGET)
        services = [
            service
            for service in state.find(NodeType.SERVICE)
            if self._is_http_service(service)
            and not service.data.get("proxy_origin_recon_attempted")
        ]
        observations = 0
        candidates: list[dict[str, Any]] = []
        edge_addresses = self._observed_edge_addresses(targets, state)

        # A target marker is intentional even when resolution or a request
        # times out: it prevents an engine retry loop on an unavailable host.
        for target in targets:
            target.data["proxy_origin_recon_attempted"] = True
            target_candidates = self._known_hostnames(target, state)
            reverse_names = self._reverse_names(target, edge_addresses)
            target_candidates.extend(reverse_names)
            target_headers = target.data.get("headers") or target.data.get("response_headers")
            target_detection = self.detect_proxy(target_headers)
            if target_detection:
                target.data["proxy_detection"] = target_detection
                target.data["proxy_detected"] = True
                target.data["proxy_provider"] = target_detection["provider"]
                observations += 1

            for service in services:
                host = self._service_host(service, state)
                if not host:
                    service.data["proxy_origin_recon_attempted"] = True
                    continue
                if self._is_hostname(host):
                    target_candidates.append(host.rstrip(".").lower())

                headers = self._service_headers(service)
                if not headers:
                    headers = self._fetch_http_headers(
                        host,
                        int(service.data.get("port") or (443 if service.data.get("name") == "https" else 80)),
                        service.data.get("name"),
                    )
                detection = self.detect_proxy(headers)
                if detection:
                    service.data["proxy_detection"] = detection
                    service.data["proxy_detected"] = True
                    service.data["proxy_provider"] = detection["provider"]
                    observations += 1
                    target.data["proxy_detection"] = self._merge_detection(
                        target.data.get("proxy_detection"), detection
                    )
                    target.data["proxy_detected"] = True
                    target.data["proxy_provider"] = target.data["proxy_detection"]["provider"]

                certificate_names: list[str] = []
                if self._is_tls_service(service):
                    certificate_names = self._get_tls_names(
                        host, int(service.data.get("port") or 443)
                    )
                    if certificate_names:
                        service.data["tls_certificate_names"] = certificate_names[:16]
                        target_candidates.extend(certificate_names)

                service.data["proxy_origin_recon_attempted"] = True

            # Resolve only names already present in the graph or in certificate
            # metadata.  No wordlists, DNS history services, or external APIs.
            if target.data.get("proxy_detection"):
                target.data.setdefault("origin_candidates", [])
                target_candidates_for_run: list[dict[str, Any]] = []
                for hostname in self._unique_names(target_candidates):
                    for address in self._resolve_hostname(hostname):
                        if self._is_edge_address(address, edge_addresses):
                            continue
                        candidate = (
                            self._candidate(
                                address,
                                hostname,
                                "dns",
                                [{"source": "dns", "hostname": hostname}],
                            )
                        )
                        candidates.append(candidate)
                        target_candidates_for_run.append(candidate)
                target.data["origin_candidates"] = self._dedupe_candidates(
                    [*target.data.get("origin_candidates", []), *target_candidates_for_run]
                )[: self._MAX_CANDIDATES]
                target.data["proxy_origin_recon_status"] = (
                    "candidates_found"
                    if target.data["origin_candidates"]
                    else "no_candidate_hostname_available"
                )
                target.data["proxy_origin_recon_note"] = (
                    "No se confirmó el origen; solo se resolvieron nombres ya observados."
                    if target.data["origin_candidates"]
                    else (
                        "El objetivo es una IP del edge y no se observó un hostname "
                        "de origen en DNS inverso, TLS o metadatos existentes."
                    )
                )

            # Hosts are useful inputs on later runs, but never represent
            # confirmation that a candidate is an origin.
            for host_node in state.find(NodeType.HOST):
                if host_node.data.get("hostname") in target_candidates:
                    host_node.data["proxy_origin_recon_attempted"] = True

        for service in services:
            # Services without a corresponding target still get a marker.
            service.data.setdefault("proxy_origin_recon_attempted", True)

        return ModuleResult(
            success=True,
            added_nodes=observations + len(candidates),
            message=(
                f"{observations} señales de proxy y "
                f"{len(candidates)} candidatos posibles observados"
            ),
            raw={
                "passive": True,
                "origin_confirmed": False,
                "candidate_count": len(candidates),
            },
        )

    @classmethod
    def _observed_edge_addresses(
        cls, targets: list[Node], state: StateGraph
    ) -> set[str]:
        """Collect literal addresses already observed for the public edge."""
        values: set[str] = set()
        for target in targets:
            known_hosts = target.data.get("known_hosts") or []
            if isinstance(known_hosts, str):
                known_hosts = [known_hosts]
            for value in (target.id, target.data.get("ip"), *known_hosts):
                try:
                    values.add(str(ipaddress.ip_address(str(value).strip("[]"))))
                except (ValueError, TypeError):
                    continue
        for port in state.find(NodeType.PORT):
            value = port.data.get("host")
            try:
                values.add(str(ipaddress.ip_address(str(value).strip("[]"))))
            except (ValueError, TypeError):
                continue
        return values

    @staticmethod
    def _is_edge_address(address: str, edge_addresses: set[str]) -> bool:
        try:
            return str(ipaddress.ip_address(address.strip("[]"))) in edge_addresses
        except ValueError:
            return False

    @classmethod
    def detect_proxy(cls, headers: Mapping[str, Any] | None) -> dict[str, Any] | None:
        """Classify common proxy/CDN response headers without trusting them."""
        if not headers or not isinstance(headers, Mapping):
            return None
        normalized = {
            str(key).lower().strip(): cls._bounded_value(value)
            for key, value in headers.items()
            if str(key).strip()
        }
        evidence: list[dict[str, str]] = []
        providers: dict[str, int] = {}

        def signal(provider: str, header: str, reason: str) -> None:
            value = normalized.get(header)
            if value:
                providers[provider] = providers.get(provider, 0) + 1
                evidence.append(
                    {
                        "source": "http_header",
                        "header": header,
                        "value": value,
                        "reason": reason,
                    }
                )

        server = normalized.get("server", "").lower()
        if "cloudflare" in server:
            signal("cloudflare", "server", "server identifies Cloudflare")
        for header, reason in (
            ("cf-ray", "Cloudflare request identifier"),
            ("cf-cache-status", "Cloudflare cache status"),
            ("cf-connecting-ip", "Cloudflare forwarding header"),
            ("cf-visitor", "Cloudflare visitor metadata"),
            ("cf-request-id", "Cloudflare request identifier"),
        ):
            signal("cloudflare", header, reason)

        if "fastly" in normalized.get("via", "").lower():
            signal("fastly", "via", "Via identifies Fastly")
        for header in ("x-served-by", "x-cache-hits"):
            signal("fastly", header, "Fastly cache metadata")

        if "cloudfront" in normalized.get("via", "").lower():
            signal("cloudfront", "via", "Via identifies CloudFront")
        for header in ("x-amz-cf-id", "x-amz-cf-pop", "x-amz-cf-status"):
            signal("cloudfront", header, "CloudFront response metadata")

        if "akamai" in server.lower() or "akamai" in normalized.get("via", "").lower():
            signal("akamai", "server" if "akamai" in server else "via", "Akamai response metadata")
        for header in ("x-akamai-transformed", "x-akamai-session-info"):
            signal("akamai", header, "Akamai response metadata")

        if "varnish" in server.lower() or normalized.get("x-varnish"):
            signal("varnish", "server" if "varnish" in server.lower() else "x-varnish", "Varnish metadata")

        if not providers:
            # Generic cache/proxy headers are useful evidence, but do not name
            # a vendor and therefore receive lower confidence.
            for header in ("via", "x-cache", "x-cache-status", "x-proxy-cache"):
                if normalized.get(header):
                    signal("unknown_proxy_or_cache", header, "generic proxy/cache header")
        if not providers:
            return None

        provider, count = max(providers.items(), key=lambda item: item[1])
        confidence = min(0.99, 0.45 + 0.15 * count)
        return {
            "detected": True,
            "provider": provider,
            "confidence": round(confidence, 2),
            "confidence_label": "high" if confidence >= 0.75 else "medium",
            "evidence": evidence[: cls._MAX_EVIDENCE],
            "origin_confirmed": False,
        }

    @classmethod
    def _detect_proxy(cls, headers: Mapping[str, Any] | None) -> dict[str, Any] | None:
        """Compatibility helper for callers that use private module helpers."""
        return cls.detect_proxy(headers)

    @staticmethod
    def _bounded_value(value: Any) -> str:
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value)
        return str(value).strip()[:256]

    @classmethod
    def _is_http_service(cls, service: Node) -> bool:
        return (service.data.get("name") or "").lower() in cls._HTTP_NAMES

    @staticmethod
    def _is_tls_service(service: Node) -> bool:
        name = (service.data.get("name") or "").lower()
        try:
            port = int(service.data.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        return name == "https" or port in {443, 8443, 9443}

    @staticmethod
    def _reverse_names(target: Node, edge_addresses: set[str]) -> list[str]:
        names: list[str] = []
        for address in edge_addresses:
            try:
                name, _, _ = socket.gethostbyaddr(address)
            except (OSError, socket.herror, socket.gaierror):
                continue
            if name and ProxyOriginRecon._is_hostname(name):
                names.append(name.rstrip(".").lower())
        return names

    @staticmethod
    def _service_host(service: Node, state: StateGraph) -> str | None:
        if service.data.get("host"):
            return str(service.data["host"])
        port_number = service.data.get("port")
        for port in state.find(NodeType.PORT, number=port_number):
            if port.data.get("host"):
                return str(port.data["host"])
        return None

    @classmethod
    def _service_headers(cls, service: Node) -> dict[str, str]:
        for key in ("headers", "response_headers", "http_headers"):
            value = service.data.get(key)
            if isinstance(value, Mapping):
                return {
                    str(header): cls._bounded_value(header_value)
                    for header, header_value in list(value.items())[:64]
                }
        # HTTPProbe currently stores Server separately; retain that evidence.
        if service.data.get("server"):
            return {"Server": cls._bounded_value(service.data["server"])}
        return {}

    def _fetch_http_headers(self, host: str, port: int, service_name: str | None) -> dict[str, str]:
        scheme = "https" if (service_name or "").lower() == "https" else "http"
        try:
            address = self._format_host(host)
            response = requests.head(
                f"{scheme}://{address}:{port}/",
                timeout=self._HTTP_TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            return {
                str(key): self._bounded_value(value)
                for key, value in list(response.headers.items())[:64]
            }
        except (requests.RequestException, OSError, ValueError):
            return {}

    @staticmethod
    def _format_host(host: str) -> str:
        try:
            address = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return host.strip()
        return f"[{address}]" if address.version == 6 else str(address)

    @classmethod
    def _known_hostnames(cls, target: Node, state: StateGraph) -> list[str]:
        values: list[str] = []
        known_hostnames = target.data.get("known_hostnames") or []
        known_hosts = target.data.get("known_hosts") or []
        if isinstance(known_hostnames, str):
            known_hostnames = [known_hostnames]
        if isinstance(known_hosts, str):
            known_hosts = [known_hosts]
        for value in (
            target.data.get("hostname"),
            target.id,
            *known_hostnames,
            *known_hosts,
        ):
            if isinstance(value, str) and value and cls._is_hostname(value):
                values.append(value.rstrip(".").lower())
        for host in state.find(NodeType.HOST):
            value = host.data.get("hostname")
            if isinstance(value, str) and cls._is_hostname(value):
                values.append(value.rstrip(".").lower())
        return list(dict.fromkeys(values))

    @staticmethod
    def _is_hostname(value: str) -> bool:
        try:
            ipaddress.ip_address(value.strip("[]"))
            return False
        except ValueError:
            return bool(value and " " not in value and "/" not in value)

    @classmethod
    def _unique_names(cls, values: Iterable[str]) -> list[str]:
        return list(dict.fromkeys(value.rstrip(".").lower() for value in values if cls._is_hostname(value)))

    @classmethod
    def _resolve_hostname(cls, hostname: str) -> list[str]:
        """Resolve A and AAAA with bounded per-family resolver calls."""
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            return [str(ipaddress.ip_address(hostname.strip("[]")))]
        except ValueError:
            pass
        addresses: list[str] = []
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(
                    hostname, None, family=family, type=socket.SOCK_STREAM
                )
            except (OSError, TimeoutError):
                continue
            for _family, _socktype, _proto, _canonname, sockaddr in infos:
                try:
                    address = str(ipaddress.ip_address(sockaddr[0]))
                except ValueError:
                    continue
                if address not in addresses:
                    addresses.append(address)
        return addresses

    def _get_tls_names(self, host: str, port: int) -> list[str]:
        """Read SAN/subject from a normal HTTPS handshake; never sends a request."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            raw_socket = socket.create_connection((host.strip("[]"), port), timeout=self._DNS_TIMEOUT)
            with raw_socket, context.wrap_socket(
                raw_socket, server_hostname=host.strip("[]")
            ) as tls_socket:
                certificate = tls_socket.getpeercert()
        except (OSError, ssl.SSLError, TimeoutError, ValueError):
            return []

        names: list[str] = []
        for kind, value in certificate.get("subjectAltName", ()):
            if kind == "DNS" and isinstance(value, str):
                names.append(value.lower().rstrip("."))
        for relative_name in certificate.get("subject", ()):
            for key, value in relative_name:
                if key in {"commonName", "CN"} and isinstance(value, str):
                    names.append(value.lower().rstrip("."))
        return list(dict.fromkeys(names))[:16]

    @classmethod
    def _candidate(
        cls,
        address: str,
        hostname: str,
        source: str,
        evidence: list[dict[str, str]],
    ) -> dict[str, Any]:
        return {
            "candidate": address,
            "hostname": hostname[:253],
            "source": source,
            "confidence": 0.35,
            "confidence_label": "low",
            "evidence": evidence[: cls._MAX_EVIDENCE],
            "origin_confirmed": False,
        }

    @classmethod
    def _dedupe_candidates(cls, candidates: Iterable[Any]) -> list[dict[str, Any]]:
        """Deduplicate IPv4/IPv6 candidates while retaining bounded evidence."""
        merged: dict[str, dict[str, Any]] = {}
        for item in candidates:
            if isinstance(item, str):
                item = {"candidate": item}
            if not isinstance(item, Mapping):
                continue
            value = item.get("candidate") or item.get("address") or item.get("ip") or item.get("hostname")
            if not value:
                continue
            value = str(value).strip()
            try:
                key = str(ipaddress.ip_address(value.strip("[]"))).lower()
            except ValueError:
                key = value.rstrip(".").lower()
            entry = dict(item)
            entry["candidate"] = value
            entry["origin_confirmed"] = False
            entry["evidence"] = list(entry.get("evidence") or [])[: cls._MAX_EVIDENCE]
            existing = merged.get(key)
            if existing is None:
                merged[key] = entry
            else:
                existing["evidence"] = (existing["evidence"] + entry["evidence"])[: cls._MAX_EVIDENCE]
                if float(entry.get("confidence", 0)) > float(existing.get("confidence", 0)):
                    existing["confidence"] = entry["confidence"]
                    existing["confidence_label"] = entry.get("confidence_label", "low")
        return list(merged.values())[: cls._MAX_CANDIDATES]

    @staticmethod
    def _merge_detection(previous: Any, current: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(previous, Mapping):
            return current
        evidence = [*previous.get("evidence", []), *current.get("evidence", [])][:12]
        result = dict(current)
        result["evidence"] = evidence
        result["confidence"] = max(float(previous.get("confidence", 0)), float(current.get("confidence", 0)))
        return result


__all__ = ["ProxyOriginRecon"]
