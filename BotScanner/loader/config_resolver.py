"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-29
Modified: 2026-01-05
File: BotScanner/loader/config_resolver.py
Description: Resolves the placeholders in the yaml configuration files
"""


import re
from typing import Any

class ConfigResolver:
    PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*(\w+)\s*\}\}")

    PATH_ALIASES = {
        "LOG_DIR": "log_dir",
        "CONFIG_DIR": "config_dir",
        "DATA_DIR": "data_dir",
        "CACHE_DIR": "cache_dir",
        "PID_DIR": "pid_dir",
        "TEMP_DIR": "temp_dir",
    }

    def __init__(self, cfg: dict[str, Any], secrets: dict[str, Any] | None = None):
        self.cfg = cfg
        self.secrets = secrets or {}
        self.resolved_paths: dict[str, Any] = {}

    def _substitute(self, value: str, context: dict[str, Any]) -> str:
        for key in self.PLACEHOLDER_PATTERN.findall(value):
            # Alias map
            if key in self.PATH_ALIASES and "paths" in context:
                path_key = self.PATH_ALIASES[key]
                if path_key in context["paths"]:
                    value = value.replace(f"{{{{ {key} }}}}", context["paths"][path_key])
            # Direct paths
            elif "paths" in context and key in context["paths"]:
                value = value.replace(f"{{{{ {key} }}}}", context["paths"][key])
            # Top-level context
            elif key in context:
                value = value.replace(f"{{{{ {key} }}}}", str(context[key]))
        return value

    def _recurse(self, obj: Any, context: dict[str, Any]) -> Any:
        if isinstance(obj, dict):
            return {k: self._recurse(v, context) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._recurse(v, context) for v in obj]
        elif isinstance(obj, str):
            return self._substitute(obj, context)
        else:
            return obj

    def resolve(self) -> dict[str, Any]:
        # Phase 1: resolve paths
        self.resolved_paths = self._recurse(self.cfg.get("paths", {}), {"paths": self.cfg.get("paths", {})})

        # Phase 2: build context with resolved paths
        context = {
            "paths": self.resolved_paths,
            "project_name": self.cfg.get("project_name", "BotScanner"),
            "vault": self.secrets,
        }

        # Phase 3: resolve full config
        resolved_cfg = self._recurse(self.cfg, context)
        resolved_cfg["paths"] = self.resolved_paths
        resolved_cfg["secrets"] = self.secrets
        return resolved_cfg