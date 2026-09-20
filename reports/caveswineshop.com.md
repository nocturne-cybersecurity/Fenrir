# Reporte de auditoría — caveswineshop.com

Generado: 2026-09-20T21:08:15.792002Z

## Resumen

- Hosts descubiertos: **2**
- Servicios identificados: **4**
- Findings: **0**
- Vulnerabilidades: **0**

## Hosts

| IP | Puertos abiertos |
|---|---|
| 23.227.38.68 | 80, 443, 8080, 8443 |
| 2620:127:f00f:8:: | — |

## Servicios

| Host | Puerto | Servicio | Producto | Versión | Extra |
|---|---|---|---|---|---|
| 23.227.38.68 | 80 | http | Cloudflare http proxy | — | error code: 1003 |
| 23.227.38.68 | 443 | http | Cloudflare http proxy | — | 400 The plain HTTP request was sent to HTTPS port |
| 23.227.38.68 | 8080 | http | Cloudflare http proxy | — | error code: 1003 |
| 23.227.38.68 | 8443 | http | Cloudflare http proxy | — | 400 The plain HTTP request was sent to HTTPS port |

## Proxy/CDN y posible origen

- Proxy/CDN detectado: **cloudflare** (confianza 0.75)
- Estado de búsqueda pasiva: **candidates_found**
- Nota: No se confirmó el origen; solo se resolvieron nombres ya observados.

| Candidato posible | Hostname | Confianza | Evidencia |
|---|---|---|---|
| 23.227.38.32 | myshopify.com | 0.35 | myshopify.com |
- El origen real no se considera confirmado.
