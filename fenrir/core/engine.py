"""Motor del pipeline: ejecuta módulos en orden de prioridad hasta agotar."""
from __future__ import annotations

from rich.console import Console

from fenrir.core.capabilities import Capability, ExecutionPolicy
from fenrir.core.state import StateGraph
from fenrir.interfaces.base import BaseModule

console = Console()


class Engine:
    def __init__(
        self,
        state: StateGraph,
        modules: list[BaseModule],
        max_iterations: int = 200,
        dry_run: bool = False,
        session_manager = None,
        policy: ExecutionPolicy | None = None,
    ) -> None:
        self.state = state
        self.modules = list(modules)
        self.max_iterations = max_iterations
        self.dry_run = dry_run
        self.session_manager = session_manager
        self.policy = policy or ExecutionPolicy()
        self.executed: list[str] = []

    def step(self) -> bool:
        candidates = [
            m for m in self.modules
            if self.policy.allows(getattr(m, "capability", Capability.READ_ONLY))
            and m.can_run(self.state)
        ]
        if not candidates:
            return False

        candidates.sort(key=lambda m: m.score(self.state), reverse=True)
        chosen = candidates[0]
        self.modules.remove(chosen)

        console.print(
            f"[cyan]▶[/cyan] [bold]{chosen.name}[/bold] "
            f"[dim](fase: {chosen.phase})[/dim]"
        )

        if self.dry_run:
            console.print("  [yellow]dry-run: no se ejecuta[/yellow]")
            return True

        # Pass session_manager to exploit executor modules
        if self.session_manager and hasattr(chosen, 'session_manager'):
            chosen.session_manager = self.session_manager
            console.print(f"[dim]  Session manager passed to {chosen.name}[/dim]")
        
        # Pass policy to modules that support it
        if self.policy and hasattr(chosen, 'policy'):
            chosen.policy = self.policy

        try:
            result = chosen.run(self.state)
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]✗ error: {exc}[/red]")
            return True

        self.executed.append(chosen.name)
        if result.success:
            console.print(f"  [green]✓[/green] {result.message}")
        else:
            console.print(f"  [yellow]·[/yellow] {result.message}")
        return True

    def run(self) -> StateGraph:
        console.rule("[bold]Pipeline iniciado")
        for _ in range(self.max_iterations):
            if not self.step():
                break
        console.rule("[bold]Pipeline finalizado")
        return self.state