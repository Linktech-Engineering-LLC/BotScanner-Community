"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-28
Modified: 2026-01-23
File: BotScanner/loader/loader_helpers.py
Description: Some Loader oriented helper functions
"""
# System Imports
import re
from typing import Any
from pathlib import Path
# Project Imports
from ..utils.common import read_project_file

PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*(\w+)\s*\}\}")
PATH_ALIASES = {
    "LOG_DIR": "log_dir",
    "CONFIG_DIR": "config_dir",
    "DATA_DIR": "data_dir",
    "CACHE_DIR": "cache_dir",
    "PID_DIR": "pid_dir",
    "TEMP_DIR": "temp_dir",
}

def deep_merge(a, b):
    """
    Deterministic deep merge for nested dictionaries.
    Values in b override values in a.
    """
    for key, value in b.items():
        if (
            key in a
            and isinstance(a[key], dict)
            and isinstance(value, dict)
        ):
            deep_merge(a[key], value)
        else:
            a[key] = value
    return a

def resolve_defaults(section: dict, context: dict) -> dict:
    """Resolve placeholders in a single config section."""
    resolved = {}
    for key, value in section.items():
        if isinstance(value, str):
            v = value
            for placeholder, actual in context.items():
                v = v.replace(f"{{{{ {placeholder} }}}}", str(actual))
            resolved[key] = v
        elif isinstance(value, dict):
            resolved[key] = resolve_defaults(value, context)
        elif isinstance(value, list):
            resolved[key] = [resolve_defaults(v, context) if isinstance(v, dict) else v for v in value]
        else:
            resolved[key] = value
    return resolved

def resolve_all_sections(cfg: dict, context: dict) -> dict:
    """Recursively resolve placeholders across the entire config tree."""
    return resolve_defaults(cfg, context)

def resolve_placeholders(cfg: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively resolve {{ KEY }} placeholders in cfg using context and context['paths'].
    Runs multiple passes until all placeholders are gone.
    """

    def substitute(value: str) -> str:
        for key in PLACEHOLDER_PATTERN.findall(value):
            # First check paths section
            if "paths" in context and key in context["paths"]:
                value = value.replace(f"{{{{ {key} }}}}", context["paths"][key])
            # Then check top-level context
            elif key in context:
                value = value.replace(f"{{{{ {key} }}}}", str(context[key]))
        return value

    def recurse(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: recurse(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [recurse(v) for v in obj]
        elif isinstance(obj, str):
            return substitute(obj)
        else:
            return obj

    # Keep resolving until stable
    prev, curr = None, cfg
    while prev != curr:
        prev = curr
        curr = recurse(curr)
    return curr
