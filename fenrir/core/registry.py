"""Autodescubrimiento de módulos: recorre fenrir/modules y registra
todas las subclases de BaseModule."""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from fenrir.interfaces.base import BaseModule


def discover_modules(package: str = "fenrir.modules") -> list[BaseModule]:
    modules: list[BaseModule] = []
    discovered_types: set[type[BaseModule]] = set()
    pkg = importlib.import_module(package)
    pkg_path = Path(pkg.__file__).parent

    for _, mod_name, _ in pkgutil.walk_packages(
        [str(pkg_path)], prefix=f"{package}."
    ):
        mod = importlib.import_module(mod_name)
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
                and not getattr(attr, "__abstract__", False)
                and attr not in discovered_types
            ):
                discovered_types.add(attr)
                modules.append(attr())
    return modules