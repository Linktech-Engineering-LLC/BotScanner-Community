"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-15
Modified: 2026-01-15
File: BotScanner/firewall/backend/helpers/ufw_utils.py
Description: UFW parsing + normalization helpers for BotScanner.
            These helpers are backend-agnostic and are used by UfwBackend
            to parse UFW CLI output and build a canonical, audit-friendly
            representation of UFW state.

"""
# System Libraries
import re
# Project Libraries

# ----------------------------------------------------------------------
# UFW: parse `ufw status numbered`
# ----------------------------------------------------------------------
def parse_ufw_status_numbered(text: str) -> list[dict]:
    """
    Parse `ufw status numbered` output into a list of rule dicts.

    Example lines:
        "[ 1] 22/tcp ALLOW IN Anywhere"
        "[ 2] 80/tcp DENY IN 203.0.113.5"
    """
    rules = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("["):
            continue

        # Extract index
        m = re.match(r"\[\s*(\d+)\]\s+(.*)", stripped)
        if not m:
            continue

        index = int(m.group(1))
        rest = m.group(2)

        # Typical pattern: "<port/proto> <action> <direction> <from>"
        parts = rest.split()
        if len(parts) < 4:
            # UFW can have slightly odd formats; keep raw if we can't parse cleanly
            rules.append(
                {
                    "index": index,
                    "raw": rest,
                }
            )
            continue

        port_proto = parts[0]
        action = parts[1]
        direction = parts[2]
        src = " ".join(parts[3:])  # can be "Anywhere", IP, etc.

        # Split port/proto
        if "/" in port_proto:
            port, proto = port_proto.split("/", 1)
        else:
            port, proto = port_proto, None

        rules.append(
            {
                "index": index,
                "port": port,
                "protocol": proto,
                "action": action,
                "direction": direction,
                "source": src,
                "raw": rest,
            }
        )

    return rules

# ----------------------------------------------------------------------
# UFW: parse `ufw status verbose`
# ----------------------------------------------------------------------
def parse_ufw_status_verbose(text: str) -> dict:
    """
    Parse `ufw status verbose` output into a structured dict.

    Example sections:
        Status: active
        Logging: on (low)
        Default: deny (incoming), allow (outgoing), disabled (routed)
    """
    data = {
        "status": None,
        "logging": None,
        "logging_level": None,
        "defaults": {},
    }

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Status: active
        if stripped.lower().startswith("status:"):
            _, value = stripped.split(":", 1)
            data["status"] = value.strip()
            continue

        # Logging: on (low)
        if stripped.lower().startswith("logging:"):
            _, value = stripped.split(":", 1)
            value = value.strip()
            # e.g. "on (low)" or "off"
            m = re.match(r"(\w+)(?:\s*\(([^)]+)\))?", value)
            if m:
                data["logging"] = m.group(1)
                if m.group(2):
                    data["logging_level"] = m.group(2)
            else:
                data["logging"] = value
            continue

        # Default: deny (incoming), allow (outgoing), disabled (routed)
        if stripped.lower().startswith("default:"):
            _, value = stripped.split(":", 1)
            value = value.strip()
            # Split by comma, then parse each "X (incoming)" piece
            for part in value.split(","):
                part = part.strip()
                m = re.match(r"(\w+)\s*\(([^)]+)\)", part)
                if m:
                    policy, scope = m.group(1), m.group(2)
                    data["defaults"][scope] = policy
            continue

    return data

# ----------------------------------------------------------------------
# UFW: parse `ufw show raw` (if you decide to use it)
# ----------------------------------------------------------------------
def parse_ufw_show_raw(text: str) -> dict:
    """
    Parse `ufw show raw` output.

    For now, this is a thin wrapper that just returns the raw text
    grouped by table markers. You can expand this later if you want
    deeper iptables-level introspection.
    """
    tables = {}
    current = None
    lines = []

    for line in text.splitlines():
        stripped = line.strip()

        # Table header: e.g. "*filter", "*nat"
        if stripped.startswith("*"):
            # flush previous
            if current and lines:
                tables[current] = "\n".join(lines)
            current = stripped[1:]
            lines = []
            continue

        # Commit marker
        if stripped.lower() == "commit":
            if current and lines:
                tables[current] = "\n".join(lines)
            current = None
            lines = []
            continue

        if current:
            lines.append(line)

    # Final flush
    if current and lines:
        tables[current] = "\n".join(lines)

    return tables

# ----------------------------------------------------------------------
# UFW: build canonical normalized structure
# ----------------------------------------------------------------------
def build_ufw_normalized_structure(
    status_verbose: dict | None = None,
    status_numbered: list[dict] | None = None,
    raw_status_verbose: str | None = None,
    raw_status_numbered: str | None = None,
    raw_show_raw: str | None = None,
    rc: dict | None = None,
    stderr: dict | None = None,
) -> dict:
    """
    Build the canonical UFW normalized structure.

    This is what UfwBackend.normalize() should return.
    """
    data = {
        "status": status_verbose or {},
        "rules": status_numbered or [],
        "raw": {},
    }

    if raw_status_verbose is not None:
        data["raw"]["status_verbose"] = raw_status_verbose

    if raw_status_numbered is not None:
        data["raw"]["status_numbered"] = raw_status_numbered

    if raw_show_raw is not None:
        data["raw"]["show_raw"] = raw_show_raw

    if rc is not None:
        data["rc"] = rc

    if stderr is not None:
        data["stderr"] = stderr

    return data


def parse_ufw_defaults(text: str):
    """
    Parse /etc/default/ufw contents.
    Extracts:
      - IPV6=yes/no
      - DEFAULT_INPUT_POLICY
      - DEFAULT_OUTPUT_POLICY
      - DEFAULT_FORWARD_POLICY
    """

    defaults = {
        "ipv6_enabled": None,
        "input_policy": None,
        "output_policy": None,
        "forward_policy": None,
    }

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # ------------------------------------------------------------
        # IPV6=yes|no
        # ------------------------------------------------------------
        if line.startswith("IPV6="):
            val = line.split("=", 1)[1].strip().lower()
            defaults["ipv6_enabled"] = (val == "yes")

        # ------------------------------------------------------------
        # DEFAULT_INPUT_POLICY="DROP"
        # ------------------------------------------------------------
        if line.startswith("DEFAULT_INPUT_POLICY"):
            m = re.search(r'DEFAULT_INPUT_POLICY\s*=\s*"?(\w+)"?', line)
            if m:
                defaults["input_policy"] = m.group(1).lower()

        # ------------------------------------------------------------
        # DEFAULT_OUTPUT_POLICY="ACCEPT"
        # ------------------------------------------------------------
        if line.startswith("DEFAULT_OUTPUT_POLICY"):
            m = re.search(r'DEFAULT_OUTPUT_POLICY\s*=\s*"?(\w+)"?', line)
            if m:
                defaults["output_policy"] = m.group(1).lower()

        # ------------------------------------------------------------
        # DEFAULT_FORWARD_POLICY="DROP"
        # ------------------------------------------------------------
        if line.startswith("DEFAULT_FORWARD_POLICY"):
            m = re.search(r'DEFAULT_FORWARD_POLICY\s*=\s*"?(\w+)"?', line)
            if m:
                defaults["forward_policy"] = m.group(1).lower()

    return defaults

def parse_ufw_raw_nft(text: str):
    """
    Parse output from `ufw show raw`.
    This is nftables syntax generated by UFW.
    We extract:
      - tables
      - chains
      - raw rule lines
    """

    nft = {
        "tables": {}
    }

    current_table = None
    current_chain = None

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # ------------------------------------------------------------
        # Detect table start:
        #   table inet ufw {
        # ------------------------------------------------------------
        m = re.match(r"table\s+(\w+)\s+(\w+)\s*\{", line)
        if m:
            family = m.group(1)
            table = m.group(2)

            nft["tables"].setdefault(family, {})
            nft["tables"][family].setdefault(table, {"chains": {}})

            current_table = (family, table)
            current_chain = None
            continue

        # ------------------------------------------------------------
        # Detect chain start:
        #   chain ufw-user-input {
        # ------------------------------------------------------------
        m = re.match(r"chain\s+([\w\-]+)\s*\{", line)
        if m and current_table:
            chain = m.group(1)

            family, table = current_table
            nft["tables"][family][table]["chains"].setdefault(chain, [])

            current_chain = chain
            continue

        # ------------------------------------------------------------
        # Detect chain end:
        #   }
        # ------------------------------------------------------------
        if line == "}":
            current_chain = None
            continue

        # ------------------------------------------------------------
        # Rule lines inside a chain
        # ------------------------------------------------------------
        if current_chain and current_table:
            family, table = current_table
            nft["tables"][family][table]["chains"][current_chain].append(line)

    return nft

def build_ufw_rule(
    action,
    direction,
    protocol,
    src,
    dst,
    sport=None,
    dport=None,
    comment=None,
    ufw_number=None,
    raw_line=None,
):
    """
    Build a canonical backend-agnostic rule object for UFW.
    Mirrors the structure used by firewalld and nftables normalization.
    """
    return {
        "action": action,          # allow | deny | reject
        "direction": direction,    # in | out
        "protocol": protocol,      # tcp | udp | any
        "src": src,                # CIDR or "any"
        "dst": dst,                # CIDR or "any"
        "sport": sport,            # None or port
        "dport": dport,            # None or port
        "comment": comment,        # optional string
        "backend_meta": {
            "ufw_number": ufw_number,  # rule number from `status numbered`
            "raw_line": raw_line,      # original UFW rule text
        },
    }
