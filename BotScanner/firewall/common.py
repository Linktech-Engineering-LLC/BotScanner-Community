"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-01
Modified: 2026-02-07
File: BotScanner/firewall/common.py
Description: Describe the purpose of this file
"""
# System Libraries
import os
import re
import json
import hashlib
import ipaddress
import socket
import psutil
from pathlib import Path
from typing import Tuple, Dict, Any, List
from copy import deepcopy
# Project Libraries
from ..net.net_tools import local_command
# Constants
SEVERITY_NO_DRIFT = "no-drift"
SEVERITY_MINOR = "minor"
SEVERITY_MODERATE = "moderate"
SEVERITY_MAJOR = "major"

SEVERITY_RANK = {
    SEVERITY_NO_DRIFT: 0,
    SEVERITY_MINOR: 1,
    SEVERITY_MODERATE: 2,
    SEVERITY_MAJOR: 3,
}
SEMANTIC_KEYS = {
    "services",
    "ports",
    "nat",
    "trusted",
    "botblock"
}


def format_structure(node: object, indent: int = 0) -> list[str]:
    """
    Recursively format dicts/lists/strings into deterministic, human-readable lines.
    Used for baseline normalization and drift-friendly output.
    """
    prefix = " " * indent
    lines: list[str] = []

    if isinstance(node, dict):
        for key, value in node.items():
            lines.append(f"{prefix}{key}:")
            lines.extend(format_structure(value, indent + 2))

    elif isinstance(node, list):
        for item in node:
            lines.extend(format_structure(item, indent + 2))

    elif isinstance(node, str):
        for line in node.splitlines():
            stripped = line.strip()

            # nftables metadata
            if stripped.startswith(("type", "flags")):
                lines.append(f"{prefix}{stripped}")

            # nftables elements { a, b, c }
            elif stripped.startswith("elements"):
                match = re.search(r'{([^}]*)}', stripped)
                if match:
                    elements = [e.strip() for e in match.group(1).split(",") if e.strip()]
                    lines.append(f"{prefix}elements:")
                    for elem in elements:
                        lines.append(f"{prefix}  - {elem}")
                else:
                    lines.append(f"{prefix}{stripped}")

            # structural lines: set foo, closing brace
            elif stripped.startswith("set ") or stripped == "}":
                lines.append(f"{prefix}{stripped}")

            # default: treat as rule line
            else:
                lines.append(f"{prefix}- {stripped}")

    else:
        # scalar fallback
        lines.append(f"{prefix}- {node}")

    return lines

def get_backend_owner(cfg: dict, backend_name: str) -> dict:
    """
    Returns a structured result describing the owner lookup.
    Never raises. Caller decides how to log or handle errors.

    return:
        { "ok": True, "owner": "system" }
        { "ok": False, "error": "backend_not_defined", "owner": None }
        { "ok": False, "error": "owner_missing", "owner": None }
    """

    fw_cfg = cfg.get("firewall", {})
    backends = fw_cfg.get("backends", {})

    # Backend not defined
    if backend_name not in backends:
        return {
            "ok": False,
            "error": "backend_not_defined",
            "owner": None
        }

    owner = backends[backend_name].get("owner")

    # Owner missing
    if not owner:
        return {
            "ok": False,
            "error": "owner_missing",
            "owner": None
        }

    # Success
    return {
        "ok": True,
        "owner": owner
    }

def verify_checksum(json_path: Path, checksum_path: Path) -> bool:
    """
    Verify that the SHA256 digest of the JSON file matches the checksum file.
    Returns True if valid, False otherwise.
    """
    # Compute digest of current JSON file
    digest = hashlib.sha256(json_path.read_bytes()).hexdigest()

    # Read checksum file
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    sha_line = next((line for line in lines if line.startswith("SHA256=")), None)

    if not sha_line:
        raise ValueError(f"No SHA256 entry found in {checksum_path}")

    expected = sha_line.split("=", 1)[1].strip()
    return digest == expected

def load_firewall_cfg(cfg, table, key):
    bs = cfg.get("botscanner", {})

    # Navigate to the table
    parts = table.split(".")
    block = bs
    for p in parts:
        block = block.get(p, {})
    
    if not block:
        return None, f"Missing configuration block '{table}'"

    # Extract the value
    value = block.get(key)
    if value is None:
        return None, f"Missing key '{key}' in '{table}'"

    # Validate against supported if present
    supported = block.get("supported")
    if supported and isinstance(value, str):
        if value not in supported:
            return None, f"Value '{value}' not in supported list {supported}"

    # Special case: compare_families
    if key == "compare_families":
        backend_supported = block.get("supported", [])
        invalid = [f for f in value if f not in backend_supported]
        if invalid:
            return None, f"Invalid families {invalid}, supported: {backend_supported}"

    return value, None

def semantic_diff(a, b):
    """
    Compare two semantic structures and return a structured diff:
      - added keys
      - removed keys
      - changed values
    """
    diff = {}

    # Keys present in A but not B → removed
    removed = {k: a[k] for k in a.keys() - b.keys()}
    if removed:
        diff["removed"] = removed

    # Keys present in B but not A → added
    added = {k: b[k] for k in b.keys() - a.keys()}
    if added:
        diff["added"] = added

    # Keys present in both → compare semantically
    changed = {}
    for k in a.keys() & b.keys():
        if k not in SEMANTIC_KEYS:
            continue  # skip backend-specific structural keys

        if isinstance(a[k], dict) and isinstance(b[k], dict):
            sub = semantic_diff(a[k], b[k])
            if sub:
                changed[k] = sub
        else:
            # Direct comparison
            if a[k] != b[k]:
                changed[k] = {"from": a[k], "to": b[k]}

    if changed:
        diff["changed"] = changed

    return diff

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sorted_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deterministically ordered dict."""
    return dict(sorted(d.items(), key=lambda x: x[0]))

def _summarize_zone_changes(added: Dict[str, Any],
                            removed: Dict[str, Any],
                            changed: Dict[str, Any]) -> Dict[str, List[str]]:
    return {
        "added": sorted(list(added.get("zones", {}).keys())),
        "removed": sorted(list(removed.get("zones", {}).keys())),
        "changed": sorted(list(changed.get("zones", {}).keys())),
    }

def _summarize_nat_changes(changed: Dict[str, Any]) -> Dict[str, str]:
    nat = changed.get("nat", {})
    masquerade = "changed" if isinstance(nat, dict) and "masquerade" in nat else "no-change"
    forward = "changed" if isinstance(nat, dict) and "forward" in nat else "no-change"

    return {
        "masquerade": masquerade,
        "forward": forward,
    }

def _summarize_trusted_changes(changed: Dict[str, Any]) -> Dict[str, Any]:
    trusted = changed.get("trusted", {})
    if not isinstance(trusted, dict) or not trusted:
        return {}

    return {
        "added": sorted(trusted.get("added", [])),
        "removed": sorted(trusted.get("removed", [])),
    }

def _summarize_botblock_changes(changed: Dict[str, Any]) -> str:
    botblock = changed.get("botblock", {})
    return "changed" if isinstance(botblock, dict) and botblock else "no-change"

def _compute_severity(summary: Dict[str, Any]) -> str:
    """Compute deterministic severity based on summary contents."""
    severity = SEVERITY_NO_DRIFT

    # 1. Zone additions/removals → moderate
    if summary["zone_changes"]["added"] or summary["zone_changes"]["removed"]:
        severity = SEVERITY_MODERATE

    # 2. Service/port changes → minor (unless already moderate)
    svc = summary["service_changes"]
    ports = summary["port_changes"]

    has_service_drift = bool(svc.get("added") or svc.get("removed"))
    has_port_drift = bool(ports.get("added") or ports.get("removed"))

    if has_service_drift or has_port_drift:
        if SEVERITY_RANK[severity] < SEVERITY_RANK[SEVERITY_MINOR]:
            severity = SEVERITY_MINOR

    # 3. NAT, trusted, botblock → major
    nat = summary["nat_changes"]
    trusted = summary["trusted_changes"]
    botblock = summary["botblock_changes"]

    has_nat_drift = (
        nat.get("masquerade") == "changed" or
        nat.get("forward") == "changed"
    )

    has_trusted_drift = bool(trusted.get("added") or trusted.get("removed"))
    has_botblock_drift = bool(botblock.get("added") or botblock.get("removed"))

    if has_nat_drift or has_trusted_drift or has_botblock_drift:
        severity = SEVERITY_MAJOR

    return severity

# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def generate_semantic_summary(result: Dict[str, Any], lgr_cfg) -> Dict[str, Any]:
    logger_factory = lgr_cfg.get("factory")
    logger = logger_factory.get_logger("drift.summary")  # type: ignore

    logger.debug("Generating semantic summary")

    # If we were passed the full diff, unwrap the inner result
    if "result" in result:
        result = deepcopy(result["result"])
    else:
        result = deepcopy(result)

    added = result.get("added", {})
    removed = result.get("removed", {})
    changed = result.get("changed", {})

    # 1. Zone-level changes (still valid)
    zone_changes = _summarize_zone_changes(added, removed, changed)

    # 2. Service-level changes (NEW)
    svc_diff = changed.get("services", {})
    service_changes = {
        "added": sorted(svc_diff.get("added", {}).keys()),
        "removed": sorted(svc_diff.get("removed", {}).keys()),
    }

    # 3. Port-level changes (NEW — ports are just services in v3)
    port_changes = {
        "added": service_changes["added"],
        "removed": service_changes["removed"],
    }

    # 4. NAT changes (NEW)
    nat_diff = changed.get("nat", {})
    nat_changes = {
        "masquerade": "changed" if "masquerade" in nat_diff.get("added", {}) or
                                   "masquerade" in nat_diff.get("removed", {}) else "no-change",
        "forward":    "changed" if "forward" in nat_diff.get("added", {}) or
                                   "forward" in nat_diff.get("removed", {}) else "no-change",
    }

    # 5. Trusted changes
    trusted_changes = changed.get("trusted", {})

    # 6. Botblock changes
    botblock_changes = changed.get("botblock", {})

    # 7. Build summary
    summary = {
        "zone_changes": zone_changes,
        "service_changes": service_changes,
        "port_changes": port_changes,
        "nat_changes": nat_changes,
        "trusted_changes": trusted_changes,
        "botblock_changes": botblock_changes,
        "overall_status": SEVERITY_NO_DRIFT,  # placeholder
    }

    # 8. Compute severity
    summary["overall_status"] = _compute_severity(summary)

    logger.debug(f"Semantic summary generated with severity: {summary['overall_status']}")

    return summary

def build_runtime(logger):
    ip_link = subprocess.check_output(["ip", "-j", "link"]).decode()
    link_data = json.loads(ip_link)

    live_ifaces = []
    bridges = {}
    iface_info = {}

    for entry in link_data:
        name = entry.get("ifname")
        if not name:
            continue

        live_ifaces.append(name)

        iface_info[name] = {
            "mtu": entry.get("mtu"),
            "state": entry.get("operstate"),
            "master": entry.get("master"),
            "flags": entry.get("flags", []),
        }

    for iface, info in iface_info.items():
        master = info.get("master")
        if master:
            if master not in bridges:
                bridges[master] = {"slaves": []}
            bridges[master]["slaves"].append(iface)

    logger.info(f"[RUNTIME] live_ifaces={live_ifaces}")
    logger.info(f"[RUNTIME] bridges={bridges}")
    logger.info(f"[RUNTIME] iface_info keys={list(iface_info.keys())}")

    return {
        "live_interfaces": live_ifaces,
        "bridges": bridges,
        "iface_info": iface_info,
    }
