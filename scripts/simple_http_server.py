#!/usr/bin/env python3
"""Servidor HTTP simple para pruebas locales de explotación."""
from __future__ import annotations

import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


class TestHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Handler que simula un servidor vulnerable para pruebas."""
    
    server_version = "ExampleServer/1.2.4"
    
    def do_GET(self):
        """Responde a peticiones GET con información del servidor."""
        self.send_response(200)
        self.send_header("Server", self.server_version)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        response = f"""
        <html>
        <head><title>Test Server</title></head>
        <body>
        <h1>Test HTTP Server for Fenrir</h1>
        <p>Server: {self.server_version}</p>
        <p>This is a test server for exploitation flow validation.</p>
        <p>Target: localhost:{self.server_port}</p>
        </body>
        </html>
        """
        self.wfile.write(response.encode())
    
    def log_message(self, format: str, *args) -> None:
        """Override para logs más limpios."""
        print(f"[{self.log_date_time_string()}] {format % args}")


def main():
    """Inicia el servidor HTTP de prueba."""
    port = 8080
    server_address = ("127.0.0.1", port)
    
    print(f"\n{'='*60}")
    print(f"  SERVIDOR HTTP DE PRUEBA PARA FENRIR")
    print(f"{'='*60}")
    print(f"\nIniciando servidor en http://127.0.0.1:{port}")
    print(f"Server version: {TestHTTPRequestHandler.server_version}")
    print(f"\nPresiona Ctrl+C para detener\n")
    
    try:
        httpd = HTTPServer(server_address, TestHTTPRequestHandler)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nServidor detenido.")
        return 0
    except OSError as e:
        print(f"\nError: {e}")
        print(f"El puerto {port} ya está en uso.")
        print(f"Usa otro puerto o detén el proceso que lo está usando.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
