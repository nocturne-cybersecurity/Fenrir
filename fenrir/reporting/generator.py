"""Genera reportes del estado: JSON y Markdown."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from fenrir.core.state import NodeType, StateGraph


def write_json(state: StateGraph, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(state.to_dict(), indent=2, default=str))
    return path


def write_markdown(state: StateGraph, path: str | Path, target: str) -> Path:
    path = Path(path)
    lines = [
        f"# Reporte de auditoría — {target}",
        f"\nGenerado: {datetime.utcnow().isoformat()}Z\n",
        "## Resumen\n",
    ]

    hosts = state.find(NodeType.HOST)
    services = state.find(NodeType.SERVICE)
    vulns = state.find(NodeType.VULN)

    lines.append(f"- Hosts descubiertos: **{len(hosts)}**")
    lines.append(f"- Servicios identificados: **{len(services)}**")
    lines.append(f"- Vulnerabilidades: **{len(vulns)}**\n")

    if hosts:
        lines.append("## Hosts\n")
        lines.append("| IP | Puertos abiertos |")
        lines.append("|---|---|")
        for h in hosts:
            ports = state.find(NodeType.PORT, host=h.id)
            port_list = ", ".join(
                str(p.data["number"]) for p in sorted(ports, key=lambda x: x.data["number"])
            )
            lines.append(f"| {h.id} | {port_list or '—'} |")
        lines.append("")

    if services:
        lines.append("## Servicios\n")
        lines.append("| Host | Puerto | Servicio | Producto | Versión | Extra |")
        lines.append("|---|---|---|---|---|---|")
        for s in services:
            port = s.data.get("port")
            host = _host_of(s, state)
            product = s.data.get("product") or "—"
            version = s.data.get("version") or "—"
            extra = s.data.get("title") or s.data.get("banner") or "—"
            extra = extra[:60].replace("|", "\\|")
            lines.append(
                f"| {host or '—'} | {port} | {s.data.get('name')} | "
                f"{product} | {version} | {extra} |"
            )
        lines.append("")

    path.write_text("\n".join(lines))
    return path


def _host_of(svc, state: StateGraph) -> str | None:
    port_num = svc.data.get("port")
    for p in state.find(NodeType.PORT, number=port_num):
        return p.data.get("host")
    return None