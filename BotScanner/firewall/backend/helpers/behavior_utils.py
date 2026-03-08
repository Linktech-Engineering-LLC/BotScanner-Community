"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-16
Modified: 2026-01-17
File: BotScanner/firewall/backend/helpers/behavior_utils.py
Description: Backend‑agnostic helpers for normalizing, validating, and comparing
            behavioral firewall models returned by backend.canonical_behavior().
            This module contains NO backend‑specific parsing logic.
            Backends extract raw behavior; this module normalizes and compares it.

"""
# System Libraries
from typing import Dict, Set, Tuple
# Project libraries
# Local Libraries
from .canonical_utils import canonical_json_safe

# ------------------------------------------------------------
# Port Normalization
# ------------------------------------------------------------

def normalize_ports(raw_ports) -> Set[Tuple[int, str]]:
    """
    Normalize a list/set of raw port definitions into a canonical set of:
        (port_number, protocol)

    Expected input formats (backend-specific):
        - ("80", "tcp")
        - (80, "tcp")
        - {"port": 80, "protocol": "tcp"}
        - objects from backend canonicalization

    This function is backend‑agnostic and only normalizes structure.
    """
    normalized = set()

    for item in raw_ports:
        if isinstance(item, tuple) and len(item) == 2:
            port, proto = item
        elif isinstance(item, dict):
            port = item.get("port")
            proto = item.get("protocol")
        else:
            # Unknown format — skip or log later
            continue

        try:
            port = int(port)
        except Exception:
            continue

        proto = str(proto).lower()
        normalized.add((port, proto))

    return normalized

# ------------------------------------------------------------
# Zone Normalization
# ------------------------------------------------------------

def normalize_zones(raw_zones: Dict) -> Dict:
    """
    Normalize zone definitions into a canonical structure:

        {
            "public": {
                "interfaces": ["eth0"],
                "policy": "drop"
            },
            "trusted": {
                "interfaces": ["br0"],
                "policy": "accept"
            }
        }

    Backends may return different shapes; this function ensures consistency.
    """
    zones = {}

    for name, z in raw_zones.items():
        interfaces = z.get("interfaces", [])
        policy = z.get("policy")

        zones[name] = {
            "interfaces": sorted(set(interfaces)),
            "policy": policy
        }

    return zones

# ------------------------------------------------------------
# Behavior Dict Validation
# ------------------------------------------------------------

def validate_behavior_dict(beh: Dict) -> bool:
    """
    Validate that a backend's canonical_behavior() dict has the correct shape.

    Required keys:
        - default_policy
        - allowed_ports
        - blocked_ports
        - zones
    """
    required = {"default_policy", "allowed_ports", "blocked_ports", "zones"}

    if not isinstance(beh, dict):
        return False

    if not required.issubset(beh.keys()):
        return False

    if not isinstance(beh["allowed_ports"], (set, list)):
        return False

    if not isinstance(beh["blocked_ports"], (set, list)):
        return False

    if not isinstance(beh["zones"], dict):
        return False

    return True

# ------------------------------------------------------------
# Behavioral Comparison
# ------------------------------------------------------------

def compare_behavioral(a_name, b_name, a_canon, b_canon):
    BEHAVIOR_KEYS = ["ipfilter", "allow", "nat", "ipset", "ipchain"]
    drift = {}

    for key in BEHAVIOR_KEYS:
        a_val = a_canon.get(key, [])
        b_val = b_canon.get(key, [])

        a_norm = canonical_json_safe(a_val)
        b_norm = canonical_json_safe(b_val)

        if a_norm != b_norm:
            drift[key] = {
                "missing_in_b": [x for x in a_norm if x not in b_norm],
                "missing_in_a": [x for x in b_norm if x not in a_norm],
            }
    print("COMPARE_BEHAVIORAL DRIFT:", drift)

    return drift