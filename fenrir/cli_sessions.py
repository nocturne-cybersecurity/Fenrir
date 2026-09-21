"""CLI commands for session management."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from fenrir.sessions.manager import SessionManager

app = typer.Typer()
console = Console()


@app.command()
def list(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Filter by target"),
    active_only: bool = typer.Option(True, "--all", help="Include closed sessions"),
) -> None:
    """List all active sessions."""
    storage_path = Path(".fenrir/sessions.json")
    
    if not storage_path.exists():
        console.print("[yellow]No sessions found[/yellow]")
        raise typer.Exit()
    
    manager = SessionManager.load(storage_path)
    sessions = manager.list_all() if not active_only else manager.list_active()
    
    if target:
        sessions = [s for s in sessions if s.target == target]
    
    if not sessions:
        console.print("[yellow]No sessions found[/yellow]")
        raise typer.Exit()
    
    table = Table(title="Active Sessions")
    table.add_column("ID", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("Port", style="blue")
    table.add_column("Type", style="magenta")
    table.add_column("User", style="yellow")
    table.add_column("Status", style="bold")
    table.add_column("Transport", style="dim")
    
    for session in sessions:
        table.add_row(
            session.id[:8],
            f"{session.target}:{session.port}",
            str(session.port),
            session.session_type.value,
            session.user or "N/A",
            session.status.value,
            session.transport or "N/A",
        )
    
    console.print(table)


@app.command()
def interact(
    session_id: str = typer.Argument(..., help="Session ID"),
) -> None:
    """Interact with a session (open shell)."""
    storage_path = Path(".fenrir/sessions.json")
    
    if not storage_path.exists():
        console.print("[red]No sessions found[/red]")
        raise typer.Exit(1)
    
    manager = SessionManager.load(storage_path)
    session = manager.get(session_id)
    
    if not session:
        console.print(f"[red]Session {session_id} not found[/red]")
        raise typer.Exit(1)
    
    if session.status.value != "active":
        console.print(f"[red]Session {session_id} is not active[/red]")
        raise typer.Exit(1)
    
    console.print(f"[green]Opening session {session_id}...[/green]")
    console.print(f"[dim]Target: {session.target}:{session.port}[/dim]")
    console.print(f"[dim]Type: {session.session_type.value}[/dim]")
    
    # TODO: Implement actual shell interaction
    console.print("[yellow]Shell interaction not yet implemented[/yellow]")
    console.print("[dim]Use SSH directly: ssh {user}@{target} -p {port}[/dim]")


@app.command()
def upload(
    session_id: str = typer.Argument(..., help="Session ID"),
    local_file: Path = typer.Argument(..., help="Local file to upload"),
    remote_path: str = typer.Argument(..., help="Remote destination path"),
) -> None:
    """Upload a file to the target via session."""
    storage_path = Path(".fenrir/sessions.json")
    
    if not storage_path.exists():
        console.print("[red]No sessions found[/red]")
        raise typer.Exit(1)
    
    manager = SessionManager.load(storage_path)
    session = manager.get(session_id)
    
    if not session:
        console.print(f"[red]Session {session_id} not found[/red]")
        raise typer.Exit(1)
    
    if not local_file.exists():
        console.print(f"[red]File {local_file} not found[/red]")
        raise typer.Exit(1)
    
    console.print(f"[green]Uploading {local_file} to {remote_path}...[/green]")
    # TODO: Implement actual upload
    console.print("[yellow]File upload not yet implemented[/yellow]")


@app.command()
def download(
    session_id: str = typer.Argument(..., help="Session ID"),
    remote_path: str = typer.Argument(..., help="Remote file path"),
    local_path: Path = typer.Argument(..., help="Local destination"),
) -> None:
    """Download a file from the target via session."""
    storage_path = Path(".fenrir/sessions.json")
    
    if not storage_path.exists():
        console.print("[red]No sessions found[/red]")
        raise typer.Exit(1)
    
    manager = SessionManager.load(storage_path)
    session = manager.get(session_id)
    
    if not session:
        console.print(f"[red]Session {session_id} not found[/red]")
        raise typer.Exit(1)
    
    console.print(f"[green]Downloading {remote_path} to {local_path}...[/green]")
    # TODO: Implement actual download
    console.print("[yellow]File download not yet implemented[/yellow]")


@app.command()
def close(
    session_id: str = typer.Argument(..., help="Session ID"),
) -> None:
    """Close a session."""
    storage_path = Path(".fenrir/sessions.json")
    
    if not storage_path.exists():
        console.print("[red]No sessions found[/red]")
        raise typer.Exit(1)
    
    manager = SessionManager.load(storage_path)
    session = manager.get(session_id)
    
    if not session:
        console.print(f"[red]Session {session_id} not found[/red]")
        raise typer.Exit(1)
    
    session.status = "closed"
    manager.save(storage_path)
    console.print(f"[green]Session {session_id} closed[/green]")
