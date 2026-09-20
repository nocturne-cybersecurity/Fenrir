"""Enum: identifica servidores HTTP(S) y captura título + headers."""
from __future__ import annotations

import requests
from urllib3.exceptions import InsecureRequestWarning

from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.interfaces.base import BaseModule, ModuleResult

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class HTTPProbe(BaseModule):
    name = "http_probe"
    phase = "enum"
    requires = [NodeType.SERVICE]
    produces = [NodeType.SERVICE]
    priority = 70

    def can_run(self, state: StateGraph) -> bool:
        http_svcs = [
            s for s in state.find(NodeType.SERVICE)
            if s.data.get("name") in ("http", "https", "http-proxy", "http-alt")
            and "title" not in s.data
        ]
        return bool(http_svcs)

    def run(self, state: StateGraph) -> ModuleResult:
        targets = [
            s for s in state.find(NodeType.SERVICE)
            if s.data.get("name") in ("http", "https", "http-proxy", "http-alt")
            and "title" not in s.data
        ]
        probed = 0
        for svc in targets:
            host = self._host_of(svc, state)
            if not host:
                continue
            port = svc.data["port"]
            scheme = "https" if svc.data["name"] == "https" else "http"
            url = f"{scheme}://{host}:{port}/"
            info = self._probe(url)
            if info:
                svc.data.update(info)
                svc.data["url"] = url
                probed += 1
        return ModuleResult(True, probed, f"{probed} servicios HTTP probados")

    def _host_of(self, svc: Node, state: StateGraph) -> str | None:
        port_num = svc.data.get("port")
        for p in state.find(NodeType.PORT, number=port_num):
            return p.data.get("host")
        return None

    def _probe(self, url: str) -> dict | None:
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        except requests.RequestException:
            return None

        title = None
        if "<title>" in r.text.lower():
            start = r.text.lower().find("<title>") + 7
            end = r.text.lower().find("</title>", start)
            if end > start:
                title = r.text[start:end].strip()[:200]

        return {
            "status_code": r.status_code,
            "server": r.headers.get("Server"),
            "title": title,
            "content_type": r.headers.get("Content-Type"),
        }