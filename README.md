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
│   │   │   ├── host_discovery.py
│   │   │   ├── dns_recon.py
│   │   │   ├── proxy_origin_recon.py
│   │   │   └── nmap_scan.py
│   │   └── enum/
│   │       ├── mysql_enum.py
│   │       ├── postgresql_enum.py
│   │       ├── redis_enum.py
│   │       ├── mongodb_enum.py
│   │       ├── memcached_enum.py
│   │       ├── ldap_enum.py
│   │       ├── ftp_enum.py
│   │       ├── smb_enum.py
│   │       ├── dns_enum.py
│   │       ├── web_enum.py
│   │       ├── http_probe.py
│   │       └── ssh_banner.py
│   ├── reporting/
│   │   └── generator.py
│   └── config/
│       └── scope.yaml
└── tests/
    └── test_state.py
```

`proxy_origin_recon` detecta señales de CDN o reverse proxy (por ejemplo,
Cloudflare) mediante cabeceras HTTP y certificados TLS. También registra
candidatos de origen de baja confianza únicamente a partir de nombres ya
conocidos y DNS local. No confirma orígenes, no fuerza cabeceras `Host`, no
usa wordlists ni consulta servicios externos como DNSDumpster.

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

## Reconocimiento pasivo de proxies/CDN

`proxy_origin_recon` observa los servicios HTTP(S) ya descubiertos y registra
señales de reverse proxies/CDN (por ejemplo `Server`, `Via`, `X-Cache` y
cabeceras `CF-*`). Para HTTPS también puede leer SAN/subject del certificado.
Resuelve únicamente el objetivo y nombres ya presentes en el grafo (incluidos
hostnames de certificados), con soporte para IPv4 e IPv6, y guarda candidatos
de origen como posibilidades con evidencia y confianza baja; nunca confirma un
origen ni intenta acceder a él. Las solicitudes de respaldo son un único
`HEAD` al servicio observado, sin seguir redirecciones. No usa servicios DNS
externos, listas de subdominios ni fuerza bruta, y cada nodo queda marcado como
intentado para evitar repeticiones.

## Aviso legal

Fenrir está pensado para uso exclusivo en entornos y objetivos donde se cuenta
con autorización explícita para realizar pruebas de seguridad. El módulo de
`scope` (whitelist/safety) existe precisamente para reforzar este límite:
úsalo siempre y no ejecutes escaneos ni enumeración contra objetivos que no
te pertenecen o para los que no tengas permiso por escrito.
