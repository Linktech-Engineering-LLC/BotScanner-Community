"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-14
Modified: 2026-02-14
File: BotScanner/firewall/canonical/builder.py
Description: Describe the purpose of this file
"""

# System Libraries
from types import SimpleNamespace
from typing import Dict, Any, List
# Project Libraries
from ..rule import Rule

class CanonicalBuilder:
    """
    v3 CanonicalBuilder:
    - Consumes YAML config + activation_map + element_map
    - Produces canonical tables, sets, chains, and rules
    - No backend logic
    - No enforcement logic
    - No drift logic
    """

    def __init__(self, yaml_cfg, activation_map, element_map):
        self.yaml_cfg = yaml_cfg
        self.activation_map = activation_map
        self.element_map = element_map

    # ------------------------------------------------------------
    # Public Entry Point
    # ------------------------------------------------------------
    def build(self) -> SimpleNamespace:
        tables = self.build_tables()
        sets = self.build_sets()
        chains = self.build_chains()
        rules = self.build_rules(tables)
        return SimpleNamespace(
            tables = tables,
            sets = sets,
            chains = chains,
            rules = rules,
        )


    # ------------------------------------------------------------
    # TABLES
    # ------------------------------------------------------------
    def build_tables(self) -> dict:
        """
        Return canonical table metadata.
        v3 supports exactly one table.
        """
        fw_cfg = self.yaml_cfg.get("firewall", {})
        table_cfg = fw_cfg.get("table")
        table_name = table_cfg["name"]

        return {
            table_name: {
                "family": table_cfg.get("family", "inet"),
                "type": table_cfg.get("type", "filter"),
            }
        }

    # ------------------------------------------------------------
    # SETS
    # ------------------------------------------------------------
    def build_sets(self) -> dict:
        """
        Build canonical set metadata from:
        - YAML (firewall.sets)
        - activation_map["sets"]
        - element_map[set_name]
        """

        fw = self.yaml_cfg.get("firewall", {})
        sets_cfg = fw.get("sets", [])
        activation_sets = self.activation_map.get("sets", {})

        canonical_sets = {}

        for entry in sets_cfg:
            set_name = entry["name"]

            act = activation_sets.get(set_name, {
                "required": False,
                "active": False,
                "supports_ipv6": False,
                "zone": None,
            })

            canonical_sets[set_name] = {
                "name": set_name,
                "type": entry.get("type", "ipv4_addr"),
                "flags": entry.get("flags", []),
                "supports_ipv6": act.get("supports_ipv6", False),
                "zone": act.get("zone"),
                "required": act.get("required", False),
                "active": act.get("active", False),
                "elements": self.element_map.get(set_name, []),
            }

        return canonical_sets

    # ------------------------------------------------------------
    # CHAINS
    # ------------------------------------------------------------
    def build_chains(self) -> dict:
        """
        Build canonical chain metadata from YAML + activation_map.
        """
        fw = self.yaml_cfg.get("firewall", {})
        chains_cfg = fw.get("chains", [])
        activation_chains = self.activation_map.get("chains", {})

        canonical_chains = {}

        for entry in chains_cfg:
            chain_name = entry.get("name")
            act = activation_chains.get(chain_name, {"required": False, "active": False})

            canonical_chains[chain_name] = {
                "name": chain_name,
                "type": entry.get("type"),
                "hook": entry.get("hook"),
                "priority": entry.get("priority"),
                "required": act.get("required", False),
                "active": act.get("active", False),
            }

        return canonical_chains

    # ------------------------------------------------------------
    # RULES
    # ------------------------------------------------------------
    def build_rules(self, canonical_tables):
        fw = self.yaml_cfg.get("firewall", {})
        rules_cfg = fw.get("rules", [])
        activation_rules = self.activation_map.get("rules", {})

        table_name, table_meta = next(iter(canonical_tables.items()))
        family = table_meta.get("family", "inet")

        canonical_rules = []

        for idx, entry in enumerate(rules_cfg):
            temp_rule = Rule(
                family=family,
                table=table_name,
                chain=entry.get("chain"),
                src_zone=entry.get("src_zone"),
                dst_zone=entry.get("dst_zone"),
                action=entry.get("action", "accept"),
                proto=entry.get("proto"),
                src=entry.get("src"),
                dst=entry.get("dst"),
                sport=entry.get("sport"),
                dport=entry.get("dport"),
                interface=entry.get("interface"),
                comment=entry.get("comment"),
            )

            act = activation_rules.get(idx)
            if not act:
                continue
            if not act.get("active") and not act.get("required"):
                continue

            final_rule = temp_rule.with_rule_id()
            canonical_rules.append(final_rule)

        return canonical_rules
    