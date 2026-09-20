"""CLI principal."""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from fenrir.core.engine import Engine
from fenrir.core.registry import discover_modules
from fenrir.core.scope import Scope, ScopeError
from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.core.storage import Storage
from fenrir.reporting.generator import write_json, write_markdown

# Importar banner desde src
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from banner import banner

app = typer.Typer(help="fenrir — framework modular de auditoría ofensiva")
console = Console()

DEFAULT_SCOPE = Path(__file__).parent / "config" / "scope.yaml"
DEFAULT_NMAP_CONFIG = Path(__file__).parent.parent / "config" / "nmap.yaml"


@app.command()
def run(
    target: str = typer.Argument(..., help="IP o dominio objetivo"),
    scope_file: Path = typer.Option(DEFAULT_SCOPE, "--scope", "-s"),
    output: Path = typer.Option(Path("reports"), "--output", "-o"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Modo simulación (no ejecuta escaneos reales)"),
    scope_check: bool = typer.Option(
        False, "--scope-check", help="Verifica que el target esté en el scope (config/scope.yaml)"
    ),
) -> None:
    """Ejecuta el pipeline completo contra un target."""
    # Mostrar banner
    banner()
    
    # 1. Scope guard (opcional)
    if scope_check:
        try:
            scope = Scope.from_yaml(scope_file)
            scope.assert_allowed(target)
        except ScopeError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(code=1)

    # 2. Estado inicial
    state = StateGraph()
    state.add_node(Node(NodeType.TARGET, target, {"ip": target}))

    # 3. Storage
    storage = Storage()
    run_id = storage.start_run(target)

    # 4. Módulos
    modules = discover_modules()
    console.print(f"[dim]Módulos cargados: {[m.name for m in modules]}[/dim]")

    # 5. Engine
    engine = Engine(state, modules, dry_run=dry_run)
    engine.run()

    # 6. Persistencia
    storage.finish_run(run_id, state)

    # 7. Reportes
    output.mkdir(parents=True, exist_ok=True)
    json_path = write_json(state, output / f"{target}.json")
    md_path = write_markdown(state, output / f"{target}.md", target)
    console.print(f"\n[green]✓ Reporte JSON:[/green] {json_path}")
    console.print(f"[green]✓ Reporte Markdown:[/green] {md_path}")


@app.command()
def runs() -> None:
    storage = Storage()
    for run_id, target, started in storage.list_runs():
        console.print(f"#{run_id}  {target}  {started}")


@app.command()
def config(
    setting: str = typer.Argument(None, help="Configuración a editar (nmap)"),
) -> None:
    """Configura opciones del framework."""
    if setting == "nmap":
        _config_nmap()
    else:
        console.print("[yellow]Uso: fenrir config <setting>[/yellow]")
        console.print("  nmap  - Configurar opciones de nmap")


def _config_nmap() -> None:
    """Configura Nmap con un menú navegable por teclado."""
    config_path = DEFAULT_NMAP_CONFIG

    if not config_path.exists():
        console.print(f"[red]Archivo de configuración no encontrado: {config_path}[/red]")
        return

    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    options = list(config.get("default_options", _default_nmap_config()["default_options"]))
    options_set = set(options)
    timing = next((option for option in options if option in _NMAP_TIMINGS), "-T4")
    ports = str(config.get("ports", ""))
    extra_options = [
        option for option in options
        if option not in {"-sV", "-Pn", "-oX", "-", timing}
        and not option.startswith("-T")
    ]
    state = {
        "version": "-sV" in options_set,
        "timing": timing,
        "ping": "-Pn" in options_set,
        "xml": "-oX" in options_set and "-" in options_set,
        "ports": ports,
        "timeout": _valid_timeout(config.get("timeout", 600)),
        "extra": extra_options,
    }

    if os.name != "nt" and not sys.stdin.isatty():
        console.print("[yellow]La configuración interactiva necesita una terminal (TTY).[/yellow]")
        return

    values = ["version", "timing", "ping", "xml", "ports", "timeout", "advanced", "save", "reset", "cancel"]
    selected = 0
    while True:
        _render_nmap_menu(state, values, selected)
        with _raw_keyboard():
            key = _read_key()
        if key == "up":
            selected = (selected - 1) % len(values)
        elif key == "down":
            selected = (selected + 1) % len(values)
        elif key in {"left", "right"}:
            _change_nmap_value(state, values[selected], key == "right")
        elif key == "enter":
            action = values[selected]
            if action == "save":
                _save_nmap_config(config_path, state)
                console.print("[green]✓ Configuración de Nmap guardada.[/green]")
                return
            if action == "reset":
                _save_nmap_config(config_path, _nmap_state_from_config(_default_nmap_config()))
                console.print("[green]✓ Configuración restaurada a valores por defecto.[/green]")
                return
            if action == "cancel":
                console.print("[yellow]Configuración cancelada.[/yellow]")
                return
            if action == "ports":
                state["ports"] = Prompt.ask("Puertos (vacío para los puertos por defecto)", default=state["ports"])
            elif action == "advanced":
                current = " ".join(state["extra"])
                extra = Prompt.ask("Opciones extra de Nmap", default=current)
                state["extra"] = extra.split()


_NMAP_TIMINGS = ("-T1", "-T2", "-T3", "-T4", "-T5")
_TIMEOUTS = (60, 120, 300, 600, 900, 1800)


def _default_nmap_config() -> dict:
    return {
        "default_options": ["-sV", "-T4", "-Pn", "-oX", "-"],
        "timeout": 600,
    }


def _valid_timeout(value: object) -> int:
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return 600
    return timeout if timeout > 0 else 600


def _nmap_state_from_config(config: dict) -> dict:
    options = list(config.get("default_options", []))
    timing = next((option for option in options if option in _NMAP_TIMINGS), "-T4")
    known = {"-sV", "-Pn", "-oX", "-", timing}
    return {
        "version": "-sV" in options,
        "timing": timing,
        "ping": "-Pn" in options,
        "xml": "-oX" in options and "-" in options,
        "ports": str(config.get("ports", "")),
        "timeout": _valid_timeout(config.get("timeout", 600)),
        "extra": [option for option in options if option not in known and not option.startswith("-T")],
    }


def _change_nmap_value(state: dict, field: str, increase: bool) -> None:
    if field in {"version", "ping", "xml"}:
        state[field] = not state[field]
    elif field == "timing":
        index = _NMAP_TIMINGS.index(state["timing"])
        state["timing"] = _NMAP_TIMINGS[(index + (1 if increase else -1)) % len(_NMAP_TIMINGS)]
    elif field == "timeout":
        index = _TIMEOUTS.index(state["timeout"]) if state["timeout"] in _TIMEOUTS else 3
        state["timeout"] = _TIMEOUTS[(index + (1 if increase else -1)) % len(_TIMEOUTS)]


def _save_nmap_config(path: Path, state: dict) -> None:
    options = []
    if state["version"]:
        options.append("-sV")
    options.append(state["timing"])
    if state["ping"]:
        options.append("-Pn")
    if state["xml"]:
        options.extend(["-oX", "-"])
    options.extend(state["extra"])
    config = {"default_options": options, "timeout": state["timeout"]}
    if state["ports"]:
        config["ports"] = state["ports"]
    with open(path, "w") as f:
        yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)


def _render_nmap_menu(state: dict, values: list[str], selected: int) -> None:
    console.clear()
    table = Table(show_header=False, box=None, expand=True, padding=(0, 1))
    table.add_column(width=2)
    table.add_column("Ajuste", style="bold cyan")
    table.add_column("Valor", justify="right", style="white")
    labels = {
        "version": ("Detección de versiones", "Activada" if state["version"] else "Desactivada"),
        "timing": ("Velocidad del escaneo", state["timing"]),
        "ping": ("Asumir host activo (-Pn)", "Activado" if state["ping"] else "Desactivado"),
        "xml": ("Salida XML para Fenrir", "Activada" if state["xml"] else "Desactivada"),
        "ports": ("Puertos", state["ports"] or "Predeterminados"),
        "timeout": ("Timeout", f'{state["timeout"]} s'),
        "advanced": ("Opciones extra", " ".join(state["extra"]) or "Ninguna"),
        "save": ("Guardar cambios", ""),
        "reset": ("Restaurar defaults", ""),
        "cancel": ("Cancelar", ""),
    }
    for index, field in enumerate(values):
        marker = "❯" if index == selected else " "
        style = "bold green" if field == "save" else None
        table.add_row(marker, labels[field][0], labels[field][1], style=style)
    console.print(Panel(table, title="[bold magenta]Fenrir · Configuración de Nmap[/bold magenta]",
                        subtitle="[dim]↑ ↓ navegar · ← → cambiar · Enter seleccionar[/dim]",
                        border_style="cyan"))


@contextmanager
def _raw_keyboard():
    if os.name == "nt" or not sys.stdin.isatty():
        yield
        return
    import termios
    import tty

    file_descriptor = sys.stdin.fileno()
    previous = termios.tcgetattr(file_descriptor)
    try:
        tty.setcbreak(file_descriptor)
        yield
    finally:
        termios.tcsetattr(file_descriptor, termios.TCSADRAIN, previous)


def _read_key() -> str:
    if os.name == "nt":
        import msvcrt
        key = msvcrt.getwch()
        if key in {"\x00", "\xe0"}:
            return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(msvcrt.getwch(), "")
        return {"\r": "enter", "\x1b": "cancel"}.get(key, "")

    key = sys.stdin.read(1)
    if key == "\x1b":
        sequence = sys.stdin.read(2)
        return {"\x1b[A": "up", "\x1b[B": "down", "\x1b[C": "right", "\x1b[D": "left"}.get(
            key + sequence, ""
        )
    return {"\n": "enter", "\r": "enter", "q": "cancel"}.get(key, "")


if __name__ == "__main__":
    app()