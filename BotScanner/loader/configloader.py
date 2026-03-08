"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-28
Modified: 2026-01-05
File: BotScanner/loader/configloader.py
Description: Loader Engine for BotScanner configurations.
"""
# System Imports
import yaml
from pathlib import Path
# Project imports
from .loader_helpers import resolve_all_sections

class ConfigLoader:
    def __init__(self, logger_factory=None, context=None, config_dir=None):
        self.logger_factory = logger_factory
        self.logger = None
        self.root_cfg = {}
        self.merged = {}
        self.loaded_files = []

        # If no config_dir is passed, resolve relative to project root
        if config_dir is None:
            project_root = Path(__file__).resolve().parents[2]
            config_dir = project_root / "BotScanner" / "etc"

        # Load all YAML configs
        self._load_config(config_dir)
        
        # Resolve placeholders if context is provided
        if context:
            self.merged = resolve_all_sections(self.merged, context)

        # Attach logger if factory is available
        if logger_factory:
            self.logger = logger_factory.get_logger("ConfigLoader")

    def resolve_context(self, context: dict):
        """Apply placeholder resolution after configs are loaded."""
        self.merged = self._resolve_placeholders(self.merged, context)
        return self.merged

    def _load_config(self, config_dir):
        cfg_dir = Path(config_dir)
        if not cfg_dir.exists():
            raise RuntimeError(f"Config directory not found: {cfg_dir}")

        for path in sorted(cfg_dir.glob("*.yml")):
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                self.merged = self._deep_merge(self.merged, data)
                self.loaded_files.append(str(path))

    def _deep_merge(self, base, new):
        """Recursively merge two dicts."""
        for k, v in new.items():
            if (
                k in base
                and isinstance(base[k], dict)
                and isinstance(v, dict)
            ):
                base[k] = self._deep_merge(base[k], v)
            else:
                base[k] = v
        return base

    def _resolve_placeholders(self, cfg, context):
        def substitute(value):
            if isinstance(value, str):
                try:
                    return value.format(**context)
                except KeyError as e:
                    raise RuntimeError(f"Missing placeholder {e} in config")
            elif isinstance(value, dict):
                return {k: substitute(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [substitute(v) for v in value]
            return value
        return substitute(cfg)

    # ------------------------------------------------------------
    # 6. Public API
    # ------------------------------------------------------------
    def get(self, dotted_path, default=None):
        """
        Retrieve a nested config value using dotted notation.
        Example: cfg.get("firewall.rules")
        """
        node = self.merged
        for part in dotted_path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def get_paths(self):
        """Return resolved paths."""
        return self.merged.get("paths", {})