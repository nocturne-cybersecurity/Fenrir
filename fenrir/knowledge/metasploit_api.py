"""Metasploit Framework API client for module lookup."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class MetasploitModule:
    """Metasploit module information."""
    fullname: str
    name: str
    type: str
    rank: str
    description: str
    references: list[str]
    authors: list[str]
    platforms: list[str]
    targets: list[str]
    options: list[dict[str, Any]]


class MetasploitAPI:
    """Client for Metasploit Framework via msfconsole RPC."""

    def __init__(self, msfconsole_path: str = "msfconsole") -> None:
        """Initialize Metasploit API client.
        
        Args:
            msfconsole_path: Path to msfconsole binary
        """
        self.msfconsole_path = msfconsole_path

    def search_modules(self, search_term: str) -> list[MetasploitModule]:
        """Search for Metasploit modules.
        
        Args:
            search_term: Search term (CVE, service name, etc.)
            
        Returns:
            List of matching modules
        """
        try:
            cmd = [
                self.msfconsole_path,
                "-q",
                "-x",
                f"search {search_term}; exit",
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            
            return self._parse_search_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  Error searching Metasploit modules: {e}")
            return []

    def get_module_info(self, module_path: str) -> MetasploitModule | None:
        """Get detailed information about a specific module.
        
        Args:
            module_path: Module path (e.g., "exploit/multi/http/log4j_header_injection")
            
        Returns:
            Module information if found, None otherwise
        """
        try:
            cmd = [
                self.msfconsole_path,
                "-q",
                "-x",
                f"use {module_path}; show options; show targets; exit",
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            
            return self._parse_module_info(result.stdout, module_path)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  Error getting module info: {e}")
            return None

    def search_by_cve(self, cve_id: str) -> list[MetasploitModule]:
        """Search for modules related to a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            
        Returns:
            List of matching modules
        """
        return self.search_modules(cve_id)

    def search_by_service(self, service: str) -> list[MetasploitModule]:
        """Search for modules for a specific service.
        
        Args:
            service: Service name (e.g., "http", "ssh", "smb")
            
        Returns:
            List of matching modules
        """
        return self.search_modules(f"type:exploit {service}")

    def _parse_search_output(self, output: str) -> list[MetasploitModule]:
        """Parse msfconsole search output."""
        modules = []
        lines = output.split("\n")
        
        for line in lines:
            # Skip header and empty lines
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            
            # Parse tab-separated output
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            
            # Format: name, type, rank, description
            fullname = parts[0].strip()
            if not fullname:
                continue
            
            module_type = "exploit" if "/exploit/" in fullname else "auxiliary"
            name = fullname.split("/")[-1]
            rank = parts[1].strip() if len(parts) > 1 else "normal"
            description = parts[2].strip() if len(parts) > 2 else ""
            
            modules.append(MetasploitModule(
                fullname=fullname,
                name=name,
                type=module_type,
                rank=rank,
                description=description,
                references=[],
                authors=[],
                platforms=[],
                targets=[],
                options=[],
            ))
        
        return modules

    def _parse_module_info(self, output: str, module_path: str) -> MetasploitModule:
        """Parse module info output."""
        name = module_path.split("/")[-1]
        module_type = "exploit" if "/exploit/" in module_path else "auxiliary"
        
        # Parse options
        options = []
        in_options = False
        for line in output.split("\n"):
            if "Module options" in line:
                in_options = True
                continue
            if in_options and line.strip() and not line.startswith("-"):
                parts = line.split()
                if len(parts) >= 2:
                    options.append({
                        "name": parts[0],
                        "current": parts[1] if len(parts) > 1 else "",
                        "required": "yes" in line.lower(),
                    })
            if in_options and line.startswith("-"):
                in_options = False
        
        return MetasploitModule(
            fullname=module_path,
            name=name,
            type=module_type,
            rank="normal",
            description="",
            references=[],
            authors=[],
            platforms=[],
            targets=[],
            options=options,
        )
