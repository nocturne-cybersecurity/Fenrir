"""CLI principal."""
from __future__ import annotations

from pathlib import Path
import sys

import typer
from rich.console import Console

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


@app.command()
def run(
    target: str = typer.Argument(..., help="IP o dominio objetivo"),
    scope_file: Path = typer.Option(DEFAULT_SCOPE, "--scope", "-s"),
    output: Path = typer.Option(Path("reports"), "--output", "-o"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Modo simulación (no ejecuta escaneos reales)"),
    no_scope_check: bool = typer.Option(
        False, "--no-scope-check", help="PELIGROSO: omite la whitelist"
    ),
) -> None:
    """Ejecuta el pipeline completo contra un target."""
    # Mostrar banner
    banner()
    
    # 1. Scope guard
    if not no_scope_check:
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
    """Lista ejecuciones previas."""
    storage = Storage()
    for run_id, target, started in storage.list_runs():
        console.print(f"#{run_id}  {target}  {started}")


if __name__ == "__main__":
    app()