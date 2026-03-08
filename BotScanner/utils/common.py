"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-25
Modified: 2026-01-05
File: BotScanner/utils/common.py
Description: Common helper functions shared across BotScanner modules
"""
# system imports
import yaml
import json
import tomllib
from pathlib import Path
from datetime import datetime
# Project Imports

# Project root is two levels up from utils/
PROJECT_ROOT = Path(__file__).parent.parents[1]

def current_timestamp() -> str:
    # Detect system timezone automatically
    now = datetime.now().astimezone()
    return now.strftime("%Y-%m-%dT%H:%M:%S %Z%z")

def parse_size(size_str: str) -> int:
    size_str = size_str.upper()
    if size_str.endswith("KB"):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith("MB"):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith("GB"):
        return int(size_str[:-2]) * 1024 * 1024 * 1024
    return int(size_str)

def read_project_file(key: str):
    """
    Read a value from pyproject.toml using a dotted key path.
    Example: "project.name" or "project.version"
    """
    project_path = PROJECT_ROOT / "pyproject.toml"
    with project_path.open("rb") as f:
        data = tomllib.load(f)

    # Walk the dotted key path
    parts = key.split(".")
    value = data
    for part in parts:
        if part not in value:
            raise KeyError(f"Key '{key}' not found in pyproject.toml")
        value = value[part]
    return value

def string_to_dictionary(value: str) -> dict:
    """
    Parse a config string like:
      'ipfilter=botfilter,manager.name=firewalld,manager.timeout=1h,kernel.name=nftables,kernel.timeout=2h'
    into a dict with nested keys.

    Handles commas inside braces by tracking nesting depth.
    Coerces values: "None"->None, "True"/"False"->bool, numeric strings->int/float.
    """
    if not value:
        return {}

    result = {}
    parts = []
    buf = []
    depth = 0

    # Split only on top-level commas
    for ch in value:
        if ch in "{[":
            depth += 1
            buf.append(ch)
        elif ch in "}]":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())

    def coerce(val: str):
        if val == "None":
            return None
        if val.lower() in ("true", "false"):
            return val.lower() == "true"
        try:
            if "." in val:
                return float(val)
            return int(val)
        except ValueError:
            return val

    for part in parts:
        if "=" not in part:
            continue
        key, raw_val = part.split("=", 1)
        val = coerce(raw_val.strip())

        # Support dotted keys for nested dicts
        keys = key.strip().split(".")
        d = result
        for k in keys[:-1]:
            if k not in d or not isinstance(d[k], dict):
                d[k] = {}
            d = d[k]
        d[keys[-1]] = val

    return result

def dict_to_string(d: dict) -> str:
    return ",".join(f"{k}={v}" for k, v in d.items())

def coerce_bool(val: str) -> bool:
    return str(val).lower() in ("1", "true", "yes", "on")

def load_yaml(path: str) -> dict:
    with open(Path(path), "r") as f:
        return yaml.safe_load(f)

def load_json(path: str) -> dict:
    with open(Path(path), "r") as f:
        return json.load(f)
    
