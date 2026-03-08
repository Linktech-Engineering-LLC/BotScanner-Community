"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-02
Modified: 2026-01-27
File: BotScanner/firewall/backend/backend.py
Description: Describe the purpose of this file
"""
# System Libraries
from abc import ABC, abstractmethod
# Project Libraries
from ..rule import Rule

class FirewallBackend(ABC):
    """Abstract interface for all firewall backends."""
    @abstractmethod
    def parse_rules(self) -> list[Rule]:
        """Parses the rules and returns a Rule Object"""
        pass
    
    @abstractmethod
    def load_rules(self):
        """Return raw backend rules (JSON, XML, CLI output, etc.)."""
        pass

    @abstractmethod
    def normalize(self, raw):
        """Normalize raw backend rules into a backend-agnostic structure."""
        pass
    
    @abstractmethod
    def status(self) -> bool:
        """
        Return True if the backend is installed and usable on this system.
        """
        pass
        
    def canonicalize(self) -> dict:
        """
        v2 unified canonicalization pipeline:
        capture → normalize → _canonicalize
        """
        return self.parse_rules()
        raw = self.capture()
        parsed = self.normalize(raw)
        canon = self._canonicalize(parsed)
        return canon

    def capture(self):
        """
        Backend-agnostic capture wrapper.
        Always returns a dict with keys: raw, rc, stderr.
        """
        data = self.load_rules()

        # load_rules() must always return a dict with raw/rc/stderr
        if not isinstance(data, dict):
            return {
                "raw": data,
                "rc": 0,
                "stderr": ""
            }

        raw = data.get("raw")
        rc = data.get("rc", 0)
        stderr = data.get("stderr", "")

        # nftables: unwrap {"ruleset": "..."} → "..."
        #if isinstance(raw, dict) and "ruleset" in raw:
        #    raw = raw["ruleset"]

        return {
            "raw": raw,
            "rc": rc,
            "stderr": stderr
        }
    
    def _extract_allowed_ports(self, fw):
        ports = set()
        for rule in fw.get("allow", []):
            if "port" in rule and "proto" in rule:
                ports.add(f"{rule['port']}/{rule['proto']}")
        return ports

    # ------------------------------------------------------------
    # Backends must implement this
    # ------------------------------------------------------------
    def _apply_rule_backend_specific(self, rule):
        raise NotImplementedError("Backend must implement rule application")

    # ------------------------------------------------------------
    # Backends must implement this
    # ------------------------------------------------------------
    def rules_for_zone(self, zone):
        raise NotImplementedError("Backend must supply rules")
    