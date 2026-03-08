"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-15
Modified: 2026-01-15
File: BotScanner/firewall/backend/helpers/iptables_utils.py
Description: iptables parsing + normalization helpers for BotScanner.
            These helpers are backend-agnostic and used by IptablesBackend
            to parse iptables/ip6tables CLI output and build a canonical,
            audit-friendly representation of rule state.
"""
# System Libraries
import re
# Project Libraries

# ----------------------------------------------------------------------
# Parse a single iptables rulespec line (from `iptables -S`)
# ----------------------------------------------------------------------
def parse_iptables_rulespec(line: str) -> dict:
    """
    Parse a single iptables rulespec line from `iptables -S`.

    Example:
        -A INPUT -p tcp --dport 22 -j ACCEPT
    """
    tokens = line.strip().split()
    if not tokens or not tokens[0].startswith("-"):
        return {"raw": line}

    rule = {
        "chain": None,
        "protocol": None,
        "src": None,
        "dst": None,
        "sport": None,
        "dport": None,
        "target": None,
        "raw": line,
    }

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok == "-A":
            rule["chain"] = tokens[i + 1]
            i += 2
            continue

        if tok == "-p":
            rule["protocol"] = tokens[i + 1]
            i += 2
            continue

        if tok == "-s":
            rule["src"] = tokens[i + 1]
            i += 2
            continue

        if tok == "-d":
            rule["dst"] = tokens[i + 1]
            i += 2
            continue

        if tok == "--sport":
            rule["sport"] = tokens[i + 1]
            i += 2
            continue

        if tok == "--dport":
            rule["dport"] = tokens[i + 1]
            i += 2
            continue

        if tok == "-j":
            rule["target"] = tokens[i + 1]
            i += 2
            continue

        i += 1

    return rule


# ----------------------------------------------------------------------
# Parse `iptables-save` output (optional but useful)
# ----------------------------------------------------------------------
def parse_iptables_save(text: str) -> dict:
    """
    Parse `iptables-save` output into tables → chains → rules.
    """
    tables = {}
    current_table = None

    for line in text.splitlines():
        stripped = line.strip()

        # Table header: *filter
        if stripped.startswith("*"):
            current_table = stripped[1:]
            tables[current_table] = {"chains": {}, "rules": []}
            continue

        # Chain definition: :INPUT ACCEPT [0:0]
        if stripped.startswith(":") and current_table:
            chain = stripped.split()[0][1:]
            tables[current_table]["chains"][chain] = stripped
            continue

        # Rule: -A INPUT ...
        if stripped.startswith("-A") and current_table:
            tables[current_table]["rules"].append(parse_iptables_rulespec(stripped))
            continue

    return tables


# ----------------------------------------------------------------------
# Build canonical normalized structure
# ----------------------------------------------------------------------
def build_iptables_normalized_structure(
    parsed_rules: list | dict | None,
    raw_rules: str | None,
    rc: dict | None,
    stderr: dict | None,
) -> dict:
    """
    Build the canonical normalized structure for iptables/ip6tables.
    """
    return {
        "rules": parsed_rules or [],
        "raw": raw_rules,
        "rc": rc,
        "stderr": stderr,
    }
