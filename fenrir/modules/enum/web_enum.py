from __future__ import annotations

from html.parser import HTMLParser
from typing import Any

import requests
from urllib3.exceptions import InsecureRequestWarning

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class _HTMLMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self._capturing_title = False
        self.meta: dict[str, str] = {}
        self.links: list[str] = []
        self.forms: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = {key: value or "" for key, value in attrs}
        if tag == "title":
            self._capturing_title = True
            self.title = ""
        if tag == "meta":
            name = (mapping.get("name") or mapping.get("property") or mapping.get("http-equiv") or "").lower()
            content = mapping.get("content")
            if name and content:
                self.meta[name] = content.strip()
        if tag == "a":
            href = mapping.get("href", "")
            if href:
                self.links.append(href)
        if tag == "link":
            href = mapping.get("href", "")
            if href:
                self.links.append(href)
        if tag == "form":
            self.forms.append(
                {
                    "action": mapping.get("action", ""),
                    "method": (mapping.get("method") or "GET").upper(),
                    "enctype": mapping.get("enctype", ""),
                }
            )

    def handle_data(self, data: str) -> None:
        if self._capturing_title:
            self.title += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._capturing_title = False


class WebEnum(BaseModule):
    name = "web_enum"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 65

    def can_run(self, state: StateGraph) -> bool:
        http_services = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if (svc.data.get("name") or "").lower() in {"http", "https", "http-proxy", "http-alt"}
            and "links" not in svc.data
        ]
        return bool(http_services)

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            svc
            for svc in state.find(NodeType.SERVICE)
            if (svc.data.get("name") or "").lower() in {"http", "https", "http-proxy", "http-alt"}
            and "links" not in svc.data
        ]

        found = 0
        for svc in targets:
            host = self._host_of(svc, state)
            if not host:
                continue
            data = self._probe(host, int(svc.data.get("port", 0)), svc.data.get("name"))
            if not data:
                continue
            svc.data.update(data)
            found += 1

        return ModuleResult(True, found, f"{found} servicios web enumerados")

    def _host_of(self, svc: Node, state: StateGraph) -> str | None:
        port_num = svc.data.get("port")
        for port in state.find(NodeType.PORT, number=port_num):
            return port.data.get("host")
        return None

    def _probe(self, host: str, port: int, service_name: str | None) -> dict[str, Any] | None:
        scheme = "https" if (service_name or "").lower() == "https" else "http"
        url = f"{scheme}://{host}:{port}/"
        try:
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        except requests.RequestException:
            return None

        parser = _HTMLMetadataParser()
        parser.feed(response.text)

        payload: dict[str, Any] = {
            "url": url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "server": response.headers.get("Server"),
            "title": parser.title.strip()[:200] if parser.title.strip() else None,
            "meta": parser.meta,
            "links": parser.links[:50],
            "forms": parser.forms[:20],
        }
        if payload["title"] is None and response.text:
            payload["title"] = response.text[:200].strip() or None
        return payload
