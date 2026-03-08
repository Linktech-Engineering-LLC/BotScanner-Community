"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-15
Modified: 2026-01-17
File: BotScanner/firewall/backend/helpers/nftables_utils.py
Description: nftables parsing + normalization helpers for BotScanner.
            These helpers are backend-agnostic and used by NftablesBackend,
            FirewalldBackend (for raw nft output), and UfwBackend (raw_nft).
"""
# System Libraries
import re
import sys
# Project Libraries

# ----------------------------------------------------------------------
# Stage 1: Extract tables, sets, chains, and raw blocks
# ----------------------------------------------------------------------
def parse_nftables_ruleset(ruleset: str):
    """
    Stage 1: Extract tables and their raw blocks (sets, chains, ct helpers, maps, etc.)
    using brace-depth tracking so nested blocks do not break parsing.
    """

    parsed = {}
    current_table = None
    brace_depth = 0

    current_block_type = None   # "set", "chain", "ct", "map", etc.
    current_block_name = None
    current_block_lines = []

    for raw_line in ruleset.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()

        # ---------------------------------------------------------
        # TABLE START
        # ---------------------------------------------------------
        if stripped.startswith("table "):
            parts = stripped.split()
            family, name = parts[1], parts[2]
            table_key = f"{family} {name}"

            parsed[table_key] = {
                "sets": {},
                "chains": {},
                "objects": {},   # ct helpers, maps, flowtables, etc.
            }

            current_table = table_key
            brace_depth = 0
            continue

        # If we are not inside a table, ignore everything
        if current_table is None:
            continue

        # ---------------------------------------------------------
        # Detect block starts (set, chain, ct helper, map, etc.)
        # ---------------------------------------------------------
        # SET
        if stripped.startswith("set "):
            current_block_type = "set"
            current_block_name = stripped.split()[1]
            current_block_lines = [line]
            brace_depth = 1
            continue

        # CHAIN
        if stripped.startswith("chain "):
            current_block_type = "chain"
            current_block_name = stripped.split()[1]
            current_block_lines = [line]
            brace_depth = 1
            continue

        # CT HELPER / OBJECT
        if stripped.startswith("ct helper "):
            current_block_type = "object"
            current_block_name = stripped.split()[2]  # helper name
            current_block_lines = [line]
            brace_depth = 1
            continue

        # MAP / FLOWTABLE / OTHER OBJECT TYPES
        if stripped.startswith("map ") or stripped.startswith("flowtable "):
            current_block_type = "object"
            current_block_name = stripped.split()[1]
            current_block_lines = [line]
            brace_depth = 1
            continue

        # ---------------------------------------------------------
        # BLOCK CONTINUATION
        # ---------------------------------------------------------
        if current_block_type:
            current_block_lines.append(line)

            # Track braces inside the block
            if "{" in stripped:
                brace_depth += stripped.count("{")
            if "}" in stripped:
                brace_depth -= stripped.count("}")

            # Block ends when brace depth returns to zero
            if brace_depth == 0:
                tbl = parsed[current_table]

                if current_block_type == "set":
                    tbl["sets"][current_block_name] = parse_nft_set_block(current_block_lines)

                elif current_block_type == "chain":
                    tbl["chains"][current_block_name] = parse_nft_chain_block(current_block_lines)

                else:  # ct helper, map, flowtable, etc.
                    tbl["objects"][current_block_name] = current_block_lines[:]

                current_block_type = None
                current_block_name = None
                current_block_lines = []

            continue

        # ---------------------------------------------------------
        # TABLE END (only when brace depth returns to zero)
        # ---------------------------------------------------------
        if stripped == "}":
            # decrement table-level brace depth
            brace_depth -= 1

            # only end table when brace depth is zero
            if brace_depth <= 0:
                current_table = None
                brace_depth = 0

            continue

        # ---------------------------------------------------------
        # Track braces at table level
        # ---------------------------------------------------------
        if "{" in stripped:
            brace_depth += stripped.count("{")
        if "}" in stripped:
            brace_depth -= stripped.count("}")

    return parsed

# ----------------------------------------------------------------------
# Stage 2: Parse SET blocks
# ----------------------------------------------------------------------
def parse_nft_set_block(lines: list[str]) -> dict:
    """
    Parse a raw nftables set block into:
        - type
        - flags
        - elements
    """

    text = "\n".join(lines)
    result = {
        "type": None,
        "flags": [],
        "elements": [],
        "raw": text,
    }

    # -------------------------
    # TYPE
    # -------------------------
    m = re.search(r"type\s+([a-zA-Z0-9_]+)", text)
    if m:
        result["type"] = m.group(1)

    # -------------------------
    # FLAGS (brace or no brace)
    # -------------------------
    # flags interval
    m = re.search(r"flags\s+([a-zA-Z0-9_]+)", text)
    if m:
        result["flags"] = [m.group(1)]

    # flags { interval, timeout }
    m = re.search(r"flags\s*\{\s*([^}]+)\s*\}", text)
    if m:
        flags = [f.strip() for f in m.group(1).split(",")]
        result["flags"] = flags

    # -------------------------
    # ELEMENTS (multi-line)
    # -------------------------
    m = re.search(r"elements\s*=\s*\{(.*?)\}", text, re.S)
    if m:
        elements_text = m.group(1)
        result["elements"] = parse_nft_set_elements(elements_text)

    return result

# ----------------------------------------------------------------------
# Stage 3: Parse CHAIN blocks
# ----------------------------------------------------------------------
def parse_nft_chain_block(lines: list[str]) -> dict:
    """
    Parse a raw nftables chain block into:
        - hook
        - priority
        - policy
        - rules (raw rule lines)
    """

    text = "\n".join(lines)

    result = {
        "hook": None,
        "priority": None,
        "policy": None,
        "rules": [],
        "raw": text,
    }

    # -------------------------
    # Extract hook, priority, policy
    # -------------------------
    m = re.search(r"hook\s+([a-zA-Z0-9_]+)", text)
    if m:
        result["hook"] = m.group(1)

    m = re.search(r"priority\s+([^\s;]+)", text)
    if m:
        result["priority"] = m.group(1)

    m = re.search(r"policy\s+([a-zA-Z0-9_]+)", text)
    if m:
        result["policy"] = m.group(1)

    # -------------------------
    # Extract rule lines
    # -------------------------
    body = [l.strip() for l in lines[1:-1] if l.strip()]
    result["rules"] = [parse_nft_rule_line(l) for l in body]

    return result

# ----------------------------------------------------------------------
# Stage 4: Parse SET elements
# ----------------------------------------------------------------------
def parse_nft_set_elements(text: str) -> list[str]:
    """
    Parse the elements inside a set block.
    Example:
        "1.2.3.4, 5.6.7.8"
    """
    elements = []

    for part in text.split(","):
        part = part.strip()
        if part:
            elements.append(part)

    return elements


# ----------------------------------------------------------------------
# Stage 5: Build canonical normalized structure
# ----------------------------------------------------------------------
def build_nft_normalized_structure(
    parsed_ruleset,
    raw_ruleset,
    rc=None,
    stderr=None,
):
    """
    Build the canonical nftables normalized structure.
    """

    data = {
        "ruleset": parsed_ruleset,
        "raw": {
            "ruleset": raw_ruleset,
        },
    }

    if rc not in (None, 0):
        data["rc"] = rc

    if stderr:
        data["stderr"] = stderr

    return data

def parse_nft_rule_line(line: str) -> dict:
    rule = {}

    # -------------------------
    # Protocols
    # -------------------------
    m = re.search(r"\b(tcp|udp|icmpv6?|icmp|ip6?)\b", line)
    if m:
        rule["proto"] = m.group(1)

    # -------------------------
    # nfproto (ipv4/ipv6)
    # -------------------------
    m = re.search(r"nfproto\s+(ipv4|ipv6)", line)
    if m:
        rule["nfproto"] = m.group(1)

    # -------------------------
    # Interface matches
    # -------------------------
    m = re.search(r"\biifname\s+\"([^\"]+)\"", line)
    if m:
        rule["iifname"] = m.group(1)

    m = re.search(r"\boifname\s+\"([^\"]+)\"", line)
    if m:
        rule["oifname"] = m.group(1)

    # Negated interface match
    m = re.search(r"\boifname\s+!=\s+\"([^\"]+)\"", line)
    if m:
        rule["oifname_not"] = m.group(1)

    # -------------------------
    # Address matches
    # -------------------------
    m = re.search(r"\bsaddr\s+([^\s]+)", line)
    if m:
        rule["saddr"] = m.group(1)

    m = re.search(r"\bdaddr\s+([^\s]+)", line)
    if m:
        rule["daddr"] = m.group(1)

    # -------------------------
    # Port matches
    # -------------------------
    m = re.search(r"\bdport\s+(\d+)", line)
    if m:
        rule["dport"] = int(m.group(1))

    m = re.search(r"\bsport\s+(\d+)", line)
    if m:
        rule["sport"] = int(m.group(1))

    # -------------------------
    # Connection tracking
    # -------------------------
    m = re.search(r"ct\s+state\s+([A-Z,]+)", line)
    if m:
        rule["ctstate"] = m.group(1).split(",")

    # -------------------------
    # NAT
    # -------------------------
    if "masquerade" in line:
        rule["nat"] = "masquerade"

    m = re.search(r"\bsnat\s+to\s+([^\s]+)", line)
    if m:
        rule["nat"] = "snat"
        rule["nat_to"] = m.group(1)

    m = re.search(r"\bdnat\s+to\s+([^\s]+)", line)
    if m:
        rule["nat"] = "dnat"
        rule["nat_to"] = m.group(1)

    # -------------------------
    # Logging
    # -------------------------
    if "log" in line:
        rule["log"] = True

    # -------------------------
    # Action
    # -------------------------
    m = re.search(r"\b(accept|drop|reject|jump)\b", line)
    if m:
        rule["action"] = m.group(1)

    # Jump target
    if rule.get("action") == "jump":
        m = re.search(r"jump\s+([^\s]+)", line)
        if m:
            rule["jump"] = m.group(1)

    return rule

def walk_chain_graph(table: dict, start_chain: str, visited=None):
    if visited is None:
        visited = set()

    if start_chain in visited:
        return []

    visited.add(start_chain)

    chain = table["chains"].get(start_chain)
    if not chain:
        return []

    collected = []

    for rule in chain.get("rules", []):
        collected.append(rule)

        if rule.get("action") == "jump":
            target = rule.get("jump")
            if target:
                collected.extend(
                    walk_chain_graph(table, target, visited)
                )

    return collected