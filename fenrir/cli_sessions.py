"""CLI commands for session management."""
from __future__ import annotations

import subprocess
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
    console.print(f"[dim]Transport: {session.transport}[/dim]")
    
    # Get credentials from metadata
    credentials = session.metadata.get("credentials", "")
    if credentials and ":" in credentials:
        username, password = credentials.split(":", 1)
    else:
        username = session.user or "anonymous"
        password = ""
    
    # Implement interaction based on transport type
    if session.transport == "ftp":
        _interact_ftp(session.target, session.port, username, password)
    elif session.transport == "ssh":
        _interact_ssh(session.target, session.port, username, password)
    else:
        console.print(f"[yellow]Transport {session.transport} not yet implemented[/yellow]")
        console.print(f"[dim]Credentials: {username}:{password if password else 'N/A'}[/dim]")


def _interact_ftp(target: str, port: int, username: str, password: str) -> None:
    """Interact with FTP session using curl or python."""
    console.print(f"[cyan]FTP Session: {username}@{target}:{port}[/cyan]")
    
    # Try using python ftplib
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(target, port)
        ftp.login(username, password)
        console.print(f"[green]✓ Connected to FTP[/green]")
        console.print(f"[dim]Current directory: {ftp.pwd()}[/dim]")
        
        # Interactive shell
        console.print("\n[cyan]FTP Commands: ls, cd <path>, get <file>, put <file>, quit[/cyan]")
        while True:
            try:
                cmd = input(f"ftp {username}@{target}:{port}> ").strip()
                if not cmd:
                    continue
                if cmd in ("quit", "exit", "q"):
                    break
                elif cmd == "ls":
                    files = []
                    ftp.retrlines('LIST', files.append)
                    for line in files:
                        console.print(line)
                elif cmd.startswith("cd "):
                    path = cmd[3:].strip()
                    ftp.cwd(path)
                    console.print(f"[dim]Current directory: {ftp.pwd()}[/dim]")
                elif cmd.startswith("get "):
                    filename = cmd[4:].strip()
                    with open(filename, 'wb') as f:
                        ftp.retrbinary(f'RETR {filename}', f.write)
                    console.print(f"[green]✓ Downloaded {filename}[/green]")
                elif cmd.startswith("put "):
                    filename = cmd[4:].strip()
                    with open(filename, 'rb') as f:
                        ftp.storbinary(f'STOR {filename}', f)
                    console.print(f"[green]✓ Uploaded {filename}[/green]")
                else:
                    console.print(f"[yellow]Unknown command: {cmd}[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
        
        ftp.quit()
        console.print("[green]FTP session closed[/green]")
        
    except ImportError:
        console.print("[yellow]ftplib not available, using curl[/yellow]")
        # Fallback to curl commands
        console.print(f"[dim]Use curl manually: curl -u {username}:{password} ftp://{target}:{port}/[/dim]")
    except Exception as e:
        console.print(f"[red]FTP connection failed: {e}[/red]")


def _interact_ssh(target: str, port: int, username: str, password: str) -> None:
    """Interact with SSH session using sshpass or manual."""
    console.print(f"[cyan]SSH Session: {username}@{target}:{port}[/cyan]")
    
    if password:
        # Try using sshpass
        try:
            subprocess.run(["sshpass", "-v"], capture_output=True, check=True)
            console.print("[green]Using sshpass for automatic login[/green]")
            cmd = ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", 
                   f"{username}@{target}", "-p", str(port)]
            subprocess.run(cmd)
            return
        except (FileNotFoundError, subprocess.CalledProcessError):
            console.print("[yellow]sshpass not found[/yellow]")
    
    # Manual connection
    console.print(f"[dim]Connect manually: ssh {username}@{target} -p {port}[/dim]")
    if password:
        console.print(f"[dim]Password: {password}[/dim]")


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
