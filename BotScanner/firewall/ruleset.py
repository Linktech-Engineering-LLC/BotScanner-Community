"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-09
Modified: 2026-02-09
File: BotScanner/firewall/ruleset.py
Description:
    Canonical rule definitions and expansion logic for BotScanner v3.
    This module converts high-level zone/service/set rules into concrete
    Rule objects (from rule.py) that the backend translators can consume.
"""
# System Libraries
from typing import Dict, List, Any
from .rule import Rule
# Project Libraries

# ---------------------------------------------------------------------------
# Zone → Chain mapping
# ---------------------------------------------------------------------------

ZONE_TO_CHAIN = {
    "public": "input",
    "local": "input",
    "trusted": "input",
    "botblock": "input",   # evaluated early
    "router": "forward",
}


# ---------------------------------------------------------------------------
# Canonical rule definitions (backend-agnostic)
# ---------------------------------------------------------------------------

CANONICAL_RULES: Dict[str, List[Dict[str, Any]]] = {
    "public": [
        {"type": "allow_established"},
        {"type": "drop_invalid"},
        {"type": "allow_services"},   # expanded from hosts.yml
    ],
    "local": [
        {"type": "allow_set", "set": "local"},
        {"type": "allow_established"},
        {"type": "drop_invalid"},
    ],
    "trusted": [
        {"type": "allow_set", "set": "trusted"},
        {"type": "allow_established"},
        {"type": "drop_invalid"},
    ],
    "botblock": [
        {"type": "drop_set", "set": "botblock"},
    ],
    "router": [
        {"type": "allow_forward", "from": "local", "to": "public"},
        {"type": "allow_established"},
        {"type": "drop_invalid"},
    ],
}


# ---------------------------------------------------------------------------
# Rule expansion helpers
# ---------------------------------------------------------------------------

def _expand_allow_established(zone: str) -> List[Rule]:
    chain = ZONE_TO_CHAIN[zone]
    return [
        Rule(
            family="inet",
            table="nftables",
            chain=chain,
            action="accept",
            comment="allow established/related",
            raw="ct state established,related accept",
        ).with_rule_id()
    ]


def _expand_drop_invalid(zone: str) -> List[Rule]:
    chain = ZONE_TO_CHAIN[zone]
    return [
        Rule(
            family="inet",
            table="nftables",
            chain=chain,
            action="drop",
            comment="drop invalid",
            raw="ct state invalid drop",
        ).with_rule_id()
    ]


def _expand_allow_set(zone: str, set_name: str) -> List[Rule]:
    chain = ZONE_TO_CHAIN[zone]
    return [
        Rule(
            family="inet",
            table="nftables",
            chain=chain,
            src=f"@{set_name}",
            action="accept",
            comment=f"allow {set_name} set",
        ).with_rule_id()
    ]


def _expand_drop_set(zone: str, set_name: str) -> List[Rule]:
    chain = ZONE_TO_CHAIN[zone]
    return [
        Rule(
            family="inet",
            table="nftables",
            chain=chain,
            src=f"@{set_name}",
            action="drop",
            comment=f"drop {set_name} set",
        ).with_rule_id()
    ]


def _expand_allow_services(zone: str, service_ports: List[Dict[str, Any]]) -> List[Rule]:
    """
    service_ports: list of dicts like:
        { "proto": "tcp", "port": 80 }
        { "proto": "tcp", "port": 443 }
    """
    chain = ZONE_TO_CHAIN[zone]
    rules = []

    for svc in service_ports:
        rules.append(
            Rule(
                family="inet",
                table="nftables",
                chain=chain,
                proto=svc["proto"],
                dport=svc["port"],
                action="accept",
                comment=f"service port {svc['port']}/{svc['proto']}",
            ).with_rule_id()
        )

    return rules


def _expand_allow_forward(zone: str, src_zone: str, dst_zone: str) -> List[Rule]:
    chain = ZONE_TO_CHAIN[zone]
    return [
        Rule(
            family="inet",
            table="nftables",
            chain=chain,
            action="accept",
            comment=f"forward {src_zone} → {dst_zone}",
            raw=f"iifname @{src_zone} oifname @{dst_zone} accept",
        ).with_rule_id()
    ]


# ---------------------------------------------------------------------------
# Main expansion entry point
# ---------------------------------------------------------------------------

def generate_rules_for_zone(
    zone: str,
    service_ports: List[Dict[str, Any]] = None,
) -> List[Rule]:
    """
    Expand canonical rules for a given zone into concrete Rule objects.

    service_ports:
        Only used for zones that include {"type": "allow_services"}.
        Should be a list of dicts: { "proto": "tcp", "port": 80 }
    """
    expanded: List[Rule] = []

    for rule_def in CANONICAL_RULES.get(zone, []):
        rtype = rule_def["type"]

        if rtype == "allow_established":
            expanded.extend(_expand_allow_established(zone))

        elif rtype == "drop_invalid":
            expanded.extend(_expand_drop_invalid(zone))

        elif rtype == "allow_set":
            expanded.extend(_expand_allow_set(zone, rule_def["set"]))

        elif rtype == "drop_set":
            expanded.extend(_expand_drop_set(zone, rule_def["set"]))

        elif rtype == "allow_services":
            if not service_ports:
                continue
            expanded.extend(_expand_allow_services(zone, service_ports))

        elif rtype == "allow_forward":
            expanded.extend(_expand_allow_forward(zone, rule_def["from"], rule_def["to"]))

        else:
            # Unknown rule type — ignore or log
            pass

    return expanded


def generate_all_rules(
    zone_services: Dict[str, List[Dict[str, Any]]]
) -> List[Rule]:
    """
    zone_services:
        {
            "public": [ { "proto": "tcp", "port": 80 }, ... ],
            "local": [],
            "trusted": [],
            ...
        }
    """
    all_rules: List[Rule] = []

    for zone in CANONICAL_RULES.keys():
        svc_ports = zone_services.get(zone, [])
        all_rules.extend(generate_rules_for_zone(zone, svc_ports))

    return all_rules
