"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-24
Modified: 2026-01-05
File: BotScanner/loader/detection.py
Description: DetectionEngine applies backend detection and service?port mapping rules
             using patterns.yml, enriching host objects with runtime metadata.
"""
# Standard library imports
from typing import Dict, Any, List
import copy


class DetectionEngine:
    """
    Applies patterns.yml rules to the merged host inventory.

    Current responsibilities:
    - backend detection (manager/kernel) based on OS/distro/host metadata
    - service ? port mapping, attaching known ports to each host

    This class does NOT:
    - load YAML (YAMLLoader does that)
    - flatten inventory (InventoryLoader)
    - merge OS/distro/host (MergeEngine)
    - perform validation (HostValidator)
    """

    def __init__(self, patterns: Dict[str, Any]):
        if not isinstance(patterns, dict):
            raise TypeError("DetectionEngine expects the patterns.yml dictionary")

        self.patterns = patterns

        # Extract pattern sections defensively; patterns.yml may grow over time
        self.backend_patterns: Dict[str, Any] = patterns.get("backend_detection", {})
        self.service_ports: Dict[str, Any] = patterns.get("service_ports", {})

    # ---------------------------------------------------------------------
    # Public entry point
    # ---------------------------------------------------------------------
    def apply(self, merged_hosts: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Given merged host objects (after MergeEngine), apply detection rules
        and return a new dictionary with backend and service_port info attached.
        """
        result: Dict[str, Dict[str, Any]] = {}

        for host_name, host_data in merged_hosts.items():
            host = copy.deepcopy(host_data)

            # Backend detection (manager/kernel)
            self._apply_backend_detection(host)

            # Service ? port mapping
            self._apply_service_ports(host)

            result[host_name] = host

        return result

    # ---------------------------------------------------------------------
    # Backend detection
    # ---------------------------------------------------------------------
    def _apply_backend_detection(self, host: Dict[str, Any]) -> None:
        """
        Use patterns.yml backend_detection rules to set:

        host["backend"] = {
            "manager": "...",
            "kernel": "..."
        }

        If host already has an explicit backend, do not override it.
        """
        # Respect explicit backend if already set
        if "backend" in host and isinstance(host["backend"], dict):
            return

        os_name = host.get("os", "")
        distro_name = host.get("distro", "")
        facts = {
            "os": os_name.lower() if isinstance(os_name, str) else "",
            "distro": distro_name.lower() if isinstance(distro_name, str) else "",
        }

        backend: Dict[str, Any] = {
            "manager": None,
            "kernel": None,
        }

        # Example structure in patterns.yml (you can adapt this to your real one):
        # backend_detection:
        #   nftables:
        #     distros: ["opensuse", "fedora"]
        #   firewalld:
        #     distros: ["fedora", "rhel"]
        #   iptables:
        #     distros: ["debian"]
        #
        # This implementation is intentionally generic.

        for backend_name, rule in self.backend_patterns.items():
            if not isinstance(rule, dict):
                continue

            distros: List[str] = [
                d.lower() for d in rule.get("distros", []) if isinstance(d, str)
            ]
            oss: List[str] = [
                o.lower() for o in rule.get("os_families", []) if isinstance(o, str)
            ]

            match_distro = facts["distro"] in distros if distros else False
            match_os = facts["os"] in oss if oss else False

            if match_distro or match_os:
                # Decide whether this is a kernel backend or a manager backend.
                # You can refine this mapping as your patterns.yml becomes more explicit.
                if rule.get("type") == "kernel":
                    backend["kernel"] = backend_name
                elif rule.get("type") == "manager":
                    backend["manager"] = backend_name

        # Only attach backend if we detected something useful
        if backend["manager"] or backend["kernel"]:
            host["backend"] = backend

    # ---------------------------------------------------------------------
    # Service ? port mapping
    # ---------------------------------------------------------------------
    def _apply_service_ports(self, host: Dict[str, Any]) -> None:
        """
        For each service listed on the host, attach a resolved list of ports:

        host["service_ports"] = {
            "apache2": ["80/tcp", "443/tcp"],
            "mysql": ["3306/tcp"],
            ...
        }

        If service_ports already exists, we merge new detections into it.
        """
        services = host.get("services")
        if not isinstance(services, list):
            return

        # Normalize existing mapping if present
        service_ports_map: Dict[str, List[str]] = {}
        if isinstance(host.get("service_ports"), dict):
            for svc, ports in host["service_ports"].items():
                if isinstance(ports, list):
                    service_ports_map[svc] = list(ports)

        for svc in services:
            if not isinstance(svc, str):
                continue

            svc_key = svc.lower()
            pattern_entry = self.service_ports.get(svc_key)
            if not isinstance(pattern_entry, dict):
                continue

            ports = pattern_entry.get("ports") or pattern_entry.get("list") or []
            if not isinstance(ports, list):
                continue

            norm_ports: List[str] = []
            for p in ports:
                if isinstance(p, str):
                    norm_ports.append(p)

            if norm_ports:
                service_ports_map[svc_key] = norm_ports

        if service_ports_map:
            host["service_ports"] = service_ports_map