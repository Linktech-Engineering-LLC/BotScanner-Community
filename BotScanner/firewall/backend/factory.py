"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-15
Modified: 2026-01-21
File: BotScanner/firewall/backend/factory.py
Description: Describe the purpose of this file
"""
# System Libraries
# Project Libraries
from ..enforcers.kernel.nftables import NftablesEnforcer
from ..enforcers.manager.firewalld import FirewalldEnforcer
from ..enforcers.manager.ufw import UfwEnforcer
from .firewalld import FirewalldBackend
from .nftables import NftablesBackend
from .ufw_backend import UfwBackend

class BackendFactory:
    """
    Lightweight factory that instantiates backend modules on demand.
    Uses lazy imports to avoid circular dependencies and unnecessary overhead.
    """

    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        
        # The backend registry — REQUIRED for CrossDriftChecker
        self._registry = {
            "firewalld": {
                "backend": FirewalldBackend,
                "enforcer": FirewalldEnforcer,
            },
            "nftables": {
                "backend": NftablesBackend,
                "enforcer": NftablesEnforcer,
            },
            "ufw": {
                "backend": UfwBackend,
                "enforcer": UfwEnforcer,
            },
        }

    def get_backend(self, backend_name: str):
        name = backend_name.lower()
        if name not in self._registry:
            raise ValueError(f"Unknown backend '{backend_name}'")

        backend_cls = self._registry[name]["backend"]
        return backend_cls(self.cfg, self.lgr_cfg)
    
    def list_backends(self) -> list:
        """
        Return a list of all known backend names.
        """
        return list(self._registry.keys())

    def get_enforcer(self, backend_name: str):
        name = backend_name.lower()
        if name not in self._registry:
            raise ValueError(f"Unknown backend '{backend_name}'")

        enforcer_cls = self._registry[name]["enforcer"]
        return enforcer_cls(self.cfg, self.lgr_cfg)
