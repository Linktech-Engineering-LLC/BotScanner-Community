"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-25
Modified: 2026-01-23
File: BotScanner/utils/init_app.py
Description: Initializes All the preload utilities and/or classes
"""
# system imports
import sys
import logging
from pathlib import Path
# project imports
from ..utils.common import read_project_file
from .factory import LoggerFactory

def init_logger(ansible_cfg: dict, console_override: bool = False):
    """
    Initialize logging configuration from ansible_cfg.
    Returns paths, log_cfg, and logger_factory.
    """

    # --- Resolve paths ---
    paths = resolve_paths()

    # --- Load logging config from YAML ---
    log_cfg = ansible_cfg.get("logging", {}).copy()
    # Provide defaults if missing
    if not log_cfg:
        log_cfg = {
            "enabled": True,
            "path": "{{ LOG_DIR }}/BotScanner.log",
            "rotate_logs": False,
            "max_age_days": 30,
        }

    # --- Deterministic placeholder substitution ---
    if "path" in log_cfg:
        log_cfg["path"] = (
            log_cfg["path"]
            .replace("{{ LOG_DIR }}", paths["LOG_DIR"])
            .replace("{{ project_name }}", ansible_cfg.get("project_name", "BotScanner"))
        )

    # --- Initialize logger factory ---
    project_name = read_project_file("project.name")

    logger_factory = LoggerFactory(log_cfg, project_name)

    return paths, log_cfg, logger_factory

def register_custom_levels(log_cfg: dict):
    """
    Register custom logging levels and attach helper methods.
    Expects: log_cfg["custom_levels"] = {"AUDIT": 25, "LIFECYCLE": 26}
    """
    custom_levels = log_cfg.get("custom_levels", {})
    for name, value in custom_levels.items():
        upper_name = name.upper()
        logging.addLevelName(value, upper_name)
        setattr(logging, upper_name, value)

        # Factory to bind value correctly
        def make_log_for_level(level_value, method_name):
            def log_for_level(self, message, *args, **kwargs):
                if self.isEnabledFor(level_value):
                    self._log(level_value, message, args, **kwargs)
            log_for_level.__name__ = method_name.lower()
            return log_for_level

        setattr(logging.Logger, name.lower(), make_log_for_level(value, name))

def resolve_paths() -> dict:
    """
    Resolve project-local paths for logs and config.
    """
    project_root = Path(__file__).resolve().parents[2]  # adjust depth if needed
    return {
        "LOG_DIR": str(project_root / "BotScanner" / "var" / "log"),
        "CONFIG_DIR": str(project_root / "BotScanner" / "etc"),
    }

