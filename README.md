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

El estado también expone `Finding` como entidad de primer nivel. Los
detectores pueden registrar hallazgos `potential` con evidencia y confianza;
un validator los transiciona explícitamente a `confirmed` o `rejected` sin
modificar directamente el servicio observado. Los findings se serializan en
el grafo y aparecen en los reportes.

## Knowledge base local

Fenrir mantiene vulnerabilidades y exploits como registros separados. La base
local vive en `data/vulnerabilities.json` y `data/exploits.json`; el detector
`version_vulnerability_detector` hace matching contra el producto y versión
observados, y `cve_validator` vuelve a comprobar la coincidencia antes de
confirmar el finding. El catálogo no consulta GitHub, Metasploit ni NVD durante
un run.

Una vulnerabilidad puede existir sin exploit público. Los exploits solo se
registran como metadata (`source`, `source_url`, requisitos, plataforma,
fiabilidad y módulo), por lo que descubrir uno nunca implica ejecutarlo.
`config/database.yaml` deja explícito que las actualizaciones automáticas están
desactivadas por defecto.

La explotación tiene una frontera adicional: `ExploitCandidate` evalúa la
compatibilidad y `ExploitResult` registra el evento separado del exploit. Por
defecto, `--exploit` habilita el descubrimiento y genera resultados
`blocked`; no carga módulos ni ejecuta código externo. Las opciones
`--post` y `--privesc` habilitan únicamente módulos de inspección y
descubrimiento controlado sobre sesiones existentes.

El alcance del pipeline se controla con la política de ejecución:

```bash
# Recon, enumeración, detección, validación y discovery de exploits
fenrir run TARGET --scope-check

# Además crea ExploitResult=blocked para revisar candidatos
fenrir run TARGET --scope-check --exploit

# Habilita post-explotación solo si ya existe una sesión en el estado
fenrir run TARGET --scope-check --exploit --post

# Habilita descubrimiento de rutas de privesc para sesiones existentes
fenrir run TARGET --scope-check --exploit --post --privesc
```

La implementación actual no crea sesiones ni ejecuta payloads: un
`ExploitResult` bloqueado es el punto de revisión y autorización. La siguiente
integración puede añadir un executor concreto para un entorno de laboratorio,
manteniendo la política, el scope, los requisitos y el registro de resultados
como condiciones obligatorias.

## Ejecutar y ver findings

Instala Fenrir en modo desarrollo y comprueba que la CLI está disponible:

```bash
source .venv/bin/activate
pip install -e ".[dev]"
fenrir --help
```

Ejecuta un target autorizado. `--scope-check` activa la whitelist de
`fenrir/config/scope.yaml` y `--output` separa los reportes de cada ejecución:

```bash
fenrir run 127.0.0.1 --scope-check --output reports/local
```

El pipeline ejecuta recon, enumeración, detección y validación cuando encuentra
metadata HTTP. El resultado se puede inspeccionar directamente:

```bash
less reports/local/127.0.0.1.md
python -m json.tool reports/local/127.0.0.1.json
```

Para probarlo de forma local, inicia un servidor HTTP en una terminal y ejecuta
Fenrir en otra:

```bash
python -m http.server 8000
fenrir run 127.0.0.1 --scope-check --output reports/local
```

Los detectores cubren HTTP y los servicios cuyo enumerador ya obtuvo metadata
de protocolo: SSH, FTP, SMB, LDAP, Redis, Memcached, MongoDB, MySQL/MariaDB y
PostgreSQL. Por ejemplo, `service_exposure_detector` crea un finding potencial
cuando un servicio no HTTP expone un banner o respuesta de protocolo, y
`service_exposure_validator` lo transiciona a `confirmed` tras comprobar de
nuevo la evidencia en el estado. De forma equivalente,
`missing_security_headers_detector` crea un finding potencial cuando observa
que faltan cabeceras de seguridad; después
`missing_security_headers_validator` lo transiciona a `confirmed`. En el
Markdown aparecerá en la sección **Findings** y en el JSON como un nodo de tipo
`finding`, con `status`, `confidence` y `evidence`.

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
