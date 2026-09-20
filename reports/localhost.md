# Reporte de auditoría — localhost

Generado: 2026-09-20T22:45:45.544533+00:00Z

## Resumen

- Hosts descubiertos: **2**
- Servicios identificados: **4**
- Findings: **3**
- Vulnerabilidades: **1**

- Exploits registrados: **0**
- Resultados de explotación: **0**
- Sesiones activas: **0**

## Findings

| Estado | Severidad | Confianza | Título |
|---|---|---|---|
| confirmed | low | 0.82 | Missing HTTP security headers |
| confirmed | info | 0.76 | Network service exposes protocol metadata |
| confirmed | high | 0.68 | Example server test vulnerability |

## Hosts

| IP | Puertos abiertos |
|---|---|
| 127.0.0.1 | 22, 80, 631, 30000 |
| ::1 | — |

## Servicios

| Host | Puerto | Servicio | Producto | Versión | Extra |
|---|---|---|---|---|---|
| 127.0.0.1 | 22 | ssh | OpenSSH | 10.0p2 Debian 7+deb13u4 | SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4 |
| 127.0.0.1 | 80 | http | Apache httpd | 2.4.68 | Apache2 Debian Default Page: It works |
| 127.0.0.1 | 631 | ipp | CUPS | 2.4 | — |
| 127.0.0.1 | 30000 | ndmps | — | — | — |
