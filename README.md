# Fenrir

Framework modular de reconocimiento y enumeración.

## Estructura del proyecto

```
fenrir/
├── pyproject.toml
├── README.md
├── fenrir/
│   ├── __init__.py
│   ├── cli.py                   # punto de entrada CLI
│   ├── core/
│   │   ├── state.py             # grafo de conocimiento
│   │   ├── engine.py            # orquestador
│   │   ├── registry.py          # autodescubrimiento de módulos
│   │   ├── scope.py             # whitelist / safety
│   │   ├── storage.py           # persistencia SQLite
│   │   └── rules.py             # motor de reglas simple
│   ├── interfaces/
│   │   └── base.py              # clase abstracta BaseModule
│   ├── modules/
│   │   ├── recon/
│   │   │   └── nmap_scan.py
│   │   └── enum/
│   │       ├── http_probe.py
│   │       └── ssh_banner.py
│   ├── reporting/
│   │   └── generator.py
│   └── config/
│       └── scope.yaml
└── tests/
    └── test_state.py
```

## Instalación (modo desarrollo)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Uso

```bash
fenrir --help
```

## Ejecutar tests

```bash
pytest
```

## Aviso legal

Fenrir está pensado para uso exclusivo en entornos y objetivos donde se cuenta
con autorización explícita para realizar pruebas de seguridad. El módulo de
`scope` (whitelist/safety) existe precisamente para reforzar este límite:
úsalo siempre y no ejecutes escaneos ni enumeración contra objetivos que no
te pertenecen o para los que no tengas permiso por escrito.
