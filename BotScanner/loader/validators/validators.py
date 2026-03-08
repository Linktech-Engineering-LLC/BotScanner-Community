"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-24
Modified: 2026-01-05
File: BotScanner/loader/validators.py
Description: HostValidator enforces structural correctness of host objects, ensuring
             required fields and types are present before enforcement.
"""
# Standard library imports
from typing import Dict, Any, List


class HostValidator:
    """
    Validates the final host objects after:
    - YAML loading
    - inventory flattening
    - OS/distro/host merging
    - backend detection
    - service ? port mapping

    This validator ensures structural correctness, not policy enforcement.
    """

    def __init__(self):
        self.errors: List[str] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def validate(self, hosts: Dict[str, Dict[str, Any]]) -> None:
        """
        Validate all hosts. Raises ValueError if any errors are found.
        """
        self.errors.clear()

        for host_name, host in hosts.items():
            self._validate_host(host_name, host)

        if self.errors:
            error_text = "\n".join(self.errors)
            raise ValueError(f"Host validation failed:\n{error_text}")

    # ------------------------------------------------------------------
    # Per-host validation
    # ------------------------------------------------------------------
    def _validate_host(self, name: str, host: Dict[str, Any]) -> None:
        """
        Validate a single host object.
        """

        # --- Required fields ------------------------------------------------
        self._require_field(name, host, "os", str)
        self._require_field(name, host, "distro", str)

        # --- Backend structure (if present) --------------------------------
        backend = host.get("backend")
        if backend is not None:
            if not isinstance(backend, dict):
                self._error(name, "'backend' must be a dictionary")
            else:
                # backend.manager and backend.kernel are optional but must be strings if present
                if "manager" in backend and backend["manager"] is not None:
                    if not isinstance(backend["manager"], str):
                        self._error(name, "'backend.manager' must be a string")

                if "kernel" in backend and backend["kernel"] is not None:
                    if not isinstance(backend["kernel"], str):
                        self._error(name, "'backend.kernel' must be a string")

        # --- Services -------------------------------------------------------
        services = host.get("services")
        if services is not None and not isinstance(services, list):
            self._error(name, "'services' must be a list of strings")

        # --- Service ports --------------------------------------------------
        svc_ports = host.get("service_ports")
        if svc_ports is not None:
            if not isinstance(svc_ports, dict):
                self._error(name, "'service_ports' must be a dictionary")
            else:
                for svc, ports in svc_ports.items():
                    if not isinstance(ports, list):
                        self._error(name, f"'service_ports.{svc}' must be a list")
                    else:
                        for p in ports:
                            if not isinstance(p, str):
                                self._error(name, f"'service_ports.{svc}' entries must be strings")

        # --- Firewall -------------------------------------------------------
        fw = host.get("firewall")
        if fw is not None and not isinstance(fw, dict):
            self._error(name, "'firewall' must be a dictionary")

        # --- Routing --------------------------------------------------------
        routing = host.get("routing")
        if routing is not None and not isinstance(routing, list):
            self._error(name, "'routing' must be a list")

        # --- GeoIP2 ---------------------------------------------------------
        geo = host.get("geoip2")
        if geo is not None and not isinstance(geo, dict):
            self._error(name, "'geoip2' must be a dictionary")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _require_field(self, host_name: str, host: Dict[str, Any], field: str, expected_type: type) -> None:
        if field not in host:
            self._error(host_name, f"Missing required field '{field}'")
            return

        if not isinstance(host[field], expected_type):
            self._error(host_name, f"Field '{field}' must be of type {expected_type.__name__}")

    def _error(self, host_name: str, message: str) -> None:
        self.errors.append(f"[{host_name}] {message}")