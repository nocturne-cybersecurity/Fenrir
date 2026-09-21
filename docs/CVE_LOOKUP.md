# CVE Lookup API Integration

Fenrir integra APIs externas para búsqueda automática de CVEs y datos de vulnerabilidades.

## APIs Soportadas

### 1. NVD API (NIST)
- **Fuente:** Oficial del gobierno de EE.UU.
- **Costo:** Gratis
- **Rate limit:** ~10 req/min (sin API key), ~50 req/min (con API key)
- **Datos:** CVEs, CVSS scores, descripciones, referencias
- **API key:** [Solicitar aquí](https://nvd.nist.gov/developers/request-an-api-key)

### 2. TridentStack API
- **Fuente:** TridentStack
- **Costo:** Gratis
- **Rate limit:** No especificado
- **Datos:** CVSS, EPSS, CISA KEV, CWEs, fixed versions, advisories
- **API key:** No requerida

### 3. Metasploit API
- **Fuente:** Metasploit Framework
- **Costo:** Gratis (requiere msfconsole instalado)
- **Datos:** Módulos de exploit, opciones, targets

## Uso

### Básico (sin API key)
```bash
fenrir run target.com --use-cve-api
```

### Con API key NVD (rate limits más altos)
```bash
fenrir run target.com --nvd-api-key YOUR_API_KEY
```

### Desactivar APIs externas
```bash
fenrir run target.com --no-cve-api
```

## Configuración

### Variables de entorno (opcional)
```bash
export NVD_API_KEY="your-api-key"
```

### Archivo de configuración (futuro)
```yaml
# config/api.yaml
nvd:
  api_key: "your-api-key"
  enabled: true

trident:
  enabled: true

metasploit:
  enabled: true
  msfconsole_path: "/usr/bin/msfconsole"
```

## Módulo CVELookupModule

El módulo `cve_lookup` se ejecuta en la fase `validation` y:

1. Busca findings con productos/versions
2. Consulta APIs externas para CVEs relacionados
3. Crea nodos de vulnerabilidad con datos enriquecidos
4. Conecta findings con CVEs

## Ejemplo de Datos

### NVD Response
```json
{
  "cve_id": "CVE-2024-1234",
  "description": "Buffer overflow in product X",
  "severity": "HIGH",
  "cvss_score": {
    "version": "3.1",
    "base_score": 8.5,
    "severity": "HIGH"
  },
  "published": "2024-01-15T10:00:00Z",
  "modified": "2024-01-20T15:30:00Z",
  "references": ["https://example.com/advisory"],
  "affected_products": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
}
```

### TridentStack Response
```json
{
  "cve_id": "CVE-2024-1234",
  "severity": "CRITICAL",
  "cvss": {"version": "3.1", "baseScore": 10.0},
  "epss": {"score": 0.94, "percentile": 0.99},
  "kev": {
    "dateAdded": "2024-03-29",
    "dueDate": "2024-04-05",
    "ransomware": false
  },
  "remediation": {
    "available": true,
    "products": [
      {
        "ecosystem": "debian",
        "product": "product",
        "fixedVersion": "2.0.0",
        "advisoryId": "DSA-1234-1"
      }
    ]
  }
}
```

## Integración con Metasploit

```python
from fenrir.knowledge.metasploit_api import MetasploitAPI

api = MetasploitAPI()

# Buscar por CVE
modules = api.search_by_cve("CVE-2021-44228")

# Buscar por servicio
modules = api.search_by_service("http")

# Info de módulo específico
info = api.get_module_info("exploit/multi/http/log4j_header_injection")
```

## Notas sobre Rapid7

**Rapid7 NO tiene API pública gratuita** para su base de datos de vulnerabilidades. Las APIs disponibles (InsightVM, InsightAppSec) requieren licencia empresarial.

Alternativas implementadas:
- **NVD API** - Fuente oficial del gobierno
- **TridentStack** - Datos enriquecidos gratis
- **Metasploit** - Módulos de exploit

## Privacidad y Datos

- NVD: Datos públicos del gobierno de EE.UU.
- TridentStack: Datos de fuentes públicas con licencias abiertas
- Metasploit: Datos de código abierto

Todos los datos se almacenan localmente en el grafo de estado de Fenrir.
