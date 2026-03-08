"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-02
Modified: 2026-01-26
File: BotScanner/firewall/backend/ufw.py
Description: UFW backend implementation for BotScanner.
"""

# Project Libraries
from ...net import sudo_run
from ..rule import Rule
from .backend import FirewallBackend
from .helpers.ufw_utils import (
    parse_ufw_status_numbered,
    parse_ufw_status_verbose,
    parse_ufw_defaults,
    parse_ufw_raw_nft,
    build_ufw_normalized_structure,
)


class UfwBackend(FirewallBackend):

    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        self.sudo_password = cfg.get("secrets", {}).get("sudo_pass")
        self.name = "ufw"
        self.family = "ufw"

        # Logger factory is passed in via lgr_cfg
        self.logger_factory = lgr_cfg.get("factory")
        self.logger = self.logger_factory.get_logger("ufw")

        # Extract backend-specific config from YAML
        fw_cfg = cfg.get("firewall", {})
        backends_cfg = fw_cfg.get("backends", {})
        self.backend_cfg = backends_cfg.get("ufw", {})

        if not self.backend_cfg:
            raise ValueError("Missing UFW backend configuration")

    # ----------------------------------------------------------------------
    # Capture raw UFW output
    # ----------------------------------------------------------------------
    def load_rules(self) -> dict:
        """
        Run all UFW capture commands defined in YAML.
        Returns:
            {
                "raw": {label: stdout},
                "rc": {label: return_code},
                "stderr": {label: stderr},
            }
        """
        command = self.backend_cfg.get("command", "ufw")
        capture_list = self.backend_cfg.get("capture", [])

        raw = {"raw": {}, "rc": {}, "stderr": {}}

        for entry in capture_list:
            if isinstance(entry, str):
                label = entry.strip().replace("-", "_").replace(" ", "_")
                raw_cmd = entry

            elif isinstance(entry, dict):
                label = entry["label"]
                raw_cmd = entry["cmd"]

            else:
                raise ValueError(f"Invalid capture entry: {entry}")

            # Interpret "!" prefix → direct command
            if raw_cmd.startswith("!"):
                cmd = raw_cmd[1:].strip()
            else:
                cmd = f"{command} {raw_cmd}"

            self.logger.debug(f"[UFW] Running: {cmd}")
            result = sudo_run(cmd, self.sudo_password)

            raw["raw"][label] = result.msg
            raw["rc"][label] = result.code
            raw["stderr"][label] = result.err

        return raw

    # ----------------------------------------------------------------------
    # Normalize UFW output into backend-agnostic structure
    # ----------------------------------------------------------------------
    def normalize(self, raw: dict) -> dict:
        """
        Normalize UFW output into a backend-agnostic structure.
        Includes:
            - UFW status verbose
            - UFW status numbered
            - UFW defaults (ufw.conf)
            - UFW raw nftables translation
        """

        # Extract raw text blocks
        raw_status_verbose = raw["raw"].get("status_verbose")
        raw_status_numbered = raw["raw"].get("status_numbered")
        raw_defaults = raw["raw"].get("defaults")
        raw_nft = raw["raw"].get("raw_nft")

        # Parse each surface
        status_verbose = (
            parse_ufw_status_verbose(raw_status_verbose)
            if raw_status_verbose else None
        )

        status_numbered = (
            parse_ufw_status_numbered(raw_status_numbered)
            if raw_status_numbered else None
        )

        defaults = (
            parse_ufw_defaults(raw_defaults)
            if raw_defaults else None
        )

        nft_parsed = (
            parse_ufw_raw_nft(raw_nft)
            if raw_nft else None
        )

        # Build canonical normalized structure
        normalized = build_ufw_normalized_structure(
            status_verbose=status_verbose,
            status_numbered=status_numbered,
            raw_status_verbose=raw_status_verbose,
            raw_status_numbered=raw_status_numbered,
            raw_show_raw=raw_nft,
            rc=raw.get("rc"),
            stderr=raw.get("stderr"),
        )

        # Attach defaults + nftables translation
        if defaults:
            normalized["defaults"] = defaults

        if nft_parsed:
            normalized["nft"] = nft_parsed

        return normalized

    def _canonicalize(self, parsed: dict) -> dict:
        """
        Convert UFW's normalized structure into the canonical schema.
        """
        return {
            "ipfilter": parsed.get("filters", []),
            "ipset": parsed.get("sets", []),
            "ipchain": parsed.get("chains", []),
            "allow": parsed.get("allows", []),
        }

    def canonical_behavior(self) -> dict:
        # For now, just return the base structure
        return super().canonical_behavior()

    def status(self) -> bool:
        result = sudo_run("ufw status", self.sudo_password)
        return result.code == 0

    def parse_rules(self) -> list[Rule]:
        rules = []
        ufw_rules = self._get_ufw_status()

        for raw in ufw_rules:
            proto, dport = self._extract_ufw_service(raw)

            r = Rule(
                table="inet",
                chain="filter_INPUT",
                action="accept",
                proto=proto,
                dport=dport,
                source="ufw",
            ).with_rule_id()

            rules.append(r)

        return rules
    