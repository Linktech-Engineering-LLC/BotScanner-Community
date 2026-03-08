"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-15
Modified: 2026-01-17
File: BotScanner/firewall/backend/helpers/firewalld_utils.py
Description: Describe the purpose of this file
"""
# System Libraries
# Project Libraries

def parse_firewalld_ruleset(text: str) -> dict:
    """
    Parse `firewall-cmd --list-all-zones` output into a structured dict.
    """

    zones = {}
    current = None

    for line in text.splitlines():
        stripped = line.strip()

        # Zone header: "public (active)"
        if stripped.endswith(")") and "(" in stripped:
            name, rest = stripped.split("(", 1)
            name = name.strip()
            active = "active" in rest
            current = name
            zones[current] = {"active": active}
            continue

        if current is None:
            continue

        # Key-value lines: "services: ssh dhcpv6-client"
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip().replace("-", "_")
            value = value.strip()

            # Empty list
            if not value:
                zones[current][key] = []

            # Boolean fields
            elif value.lower() in ("yes", "on", "enabled"):
                zones[current][key] = True
            elif value.lower() in ("no", "off", "disabled"):
                zones[current][key] = False

            # Rich rules (multi-line)
            elif key == "rich rules":
                zones[current][key] = value.splitlines()

            # Normal list fields
            else:
                zones[current][key] = value.split()

    return zones