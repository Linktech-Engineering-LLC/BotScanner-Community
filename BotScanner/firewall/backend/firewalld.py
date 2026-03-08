"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-02
Modified: 2026-01-28
File: BotScanner/firewall/backend/firewalld.py
Description: firewalld backend implementation for BotScanner.
"""

# System Libraries
import json
# Project Libraries
from ...net import sudo_run
from ..rule import Rule
from .backend import FirewallBackend
from .helpers.nftables_utils import (
    parse_nftables_ruleset,
)
from .helpers.firewalld_utils import parse_firewalld_ruleset
from .mixin import NftablesMixin

class FirewalldBackend(NftablesMixin, FirewallBackend):

    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        self.sudo_password = cfg.get("secrets", {}).get("sudo_pass")
        self.name = "firewalld"
        self.family = "firewalld"

        # Logger factory is passed in via lgr_cfg
        self.logger_factory = lgr_cfg.get("factory")
        self.logger = self.logger_factory.get_logger("firewalld") # type: ignore

        # Extract backend-specific config from YAML
        fw_cfg = cfg.get("firewall", {})
        backends_cfg = fw_cfg.get("backends", {})
        self.backend_cfg = backends_cfg.get(self.name, {})
        if not self.backend_cfg:
            raise ValueError(f"Missing {self.name} backend configuration")

        # Load service→port mapping from YAML
        self.service_port_map = self.cfg.get("services", {}).get("ports", {})

    # ----------------------------------------------------------------------
    # Capture raw firewalld output
    # ----------------------------------------------------------------------
    def load_rules(self) -> dict:
        """
        Run all firewalld capture commands defined in YAML.
        Returns:
            {
                "raw": {label: stdout},
                "rc": {label: return_code},
                "stderr": {label: stderr},
            }
        """
        command = self.backend_cfg.get("command", "firewall-cmd")
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

            self.logger.debug(f"[FIREWALLD] Running: {cmd}")
            result = sudo_run(cmd, self.sudo_password)

            raw["raw"][label] = result.msg
            raw["rc"][label] = result.code
            raw["stderr"][label] = result.err

        return raw

    # ----------------------------------------------------------------------
    # Normalize firewalld output into backend-agnostic structure
    # ----------------------------------------------------------------------
    def normalize(self, raw: dict) -> dict:
        """
        Normalize firewalld capture into backend-local raw structures.

        Produces:
            {
                "zones": <parsed firewalld zones or None>,
                "nft": <parsed nftables ruleset or None>,
                "rc": <return code>,
                "stderr": <stderr text>,
            }

        Never raises. Always logs. Always returns a dict.
        """

        normalized = {
            "zones": None,
            "nft": None,
            "rc": raw.get("rc"),
            "stderr": raw.get("stderr"),
        }

        # ---------------------------------------------------------
        # 1. Extract nftables ruleset (actual firewall state)
        # ---------------------------------------------------------
        nft_raw = None
        raw_section = raw.get("raw", {})

        if isinstance(raw_section, dict):
            # Look for any key containing both "nft" and "ruleset"
            for key, value in raw_section.items():
                if "nft" in key and "ruleset" in key:
                    nft_raw = value
                    break

        if isinstance(nft_raw, str) and nft_raw.strip():
            try:
                parsed = parse_nftables_ruleset(nft_raw)
                normalized["nft"] = parsed
            except Exception as exc:
                self.logger.error(f"[FIREWALLD] Failed to parse nftables ruleset: {exc}")
                normalized["nft"] = None

        # ---------------------------------------------------------
        # 2. Extract firewalld zones (intent)
        # ---------------------------------------------------------
        zones_raw = None

        if isinstance(raw_section, dict):
            # Common capture patterns:
            #   raw["raw"]["zones"]
            #   raw["raw"]["list_all_zones"]
            zones_raw = raw_section.get("zones") or raw_section.get("list_all_zones")

        if zones_raw:
            try:
                normalized["zones"] = parse_firewalld_ruleset(zones_raw)
            except Exception as exc:
                self.logger.error(f"[FIREWALLD] Failed to parse firewalld zones: {exc}")
                normalized["zones"] = None

        return normalized
        
    # ------------------------------------------------------------
    # Backend-specific extraction
    # ------------------------------------------------------------

    def status(self) -> bool:
        result = sudo_run("firewall-cmd --state", self.sudo_password)
        return result.code == 0 and result.msg.strip() == "running"

    def parse_rules(self) -> list[Rule]:
        """
        Parse firewalld state into canonical Rule objects.
        This is the top-level entry point for the backend.
        """

        # 1. Capture raw backend output
        raw = self.capture()

        # 2. Normalize raw structures (zones + nft)
        parsed = self.normalize(raw)

        zones = parsed.get("zones")
        nft = parsed.get("nft")

        rules: list[Rule] = []

        # 3. Convert firewalld intent (zones) → Rule objects
        if zones:
            rules.extend(self._rules_from_zones(zones))

        # 4. Convert nftables kernel state → Rule objects
        if nft:
            rules.extend(self._rules_from_nft(nft))

        return rules

    def _rules_from_zones(self, zones: dict) -> list[Rule]:
        """
        Convert firewalld zone intent into canonical Rule objects.

        Handles:
            - explicit ports
            - services → ports expansion
            - interfaces
            - sources
            - masquerade
            - forward
            - trusted/botblock (if present)
            - rich rules (if present)

        Each semantic firewall action becomes a Rule object.
        """

        rules: list[Rule] = []

        # Firewalld service → port map (loaded in normalize or __init__)
        service_map = self.service_port_map or {}

        for zone_name, z in zones.items():

            interfaces = z.get("interfaces", [])
            sources = z.get("sources", [])

            # ---------------------------------------------------------
            # 1. Explicit ports (e.g., port=80, protocol=tcp)
            # ---------------------------------------------------------
            for entry in z.get("ports", []):
                port = entry.get("port")
                proto = entry.get("proto")
                if not port or not proto:
                    continue

                rules.append(
                    Rule(
                        family="inet",
                        table="filter",
                        chain="INPUT",
                        protocol=proto,
                        dport=int(port),
                        action="accept",
                        interface=interfaces or None,
                        src=sources or None,
                        comment=f"firewalld:{zone_name}:port",
                    ).with_rule_id()
                )

            # ---------------------------------------------------------
            # 2. Services → expand via service_map
            # ---------------------------------------------------------
            for svc in z.get("services", []):
                mapping = self.service_port_map.get(svc)
                if not mapping:
                    continue

                port = mapping.get("port")
                protos = mapping.get("proto", [])

                if not port or not protos:
                    continue

                for proto in protos:
                    rules.append(
                        Rule(
                            family="inet",
                            table="filter",
                            chain="INPUT",
                            proto=proto,
                            dport=int(port),
                            action="accept",
                            interface=interfaces or None,
                            src=sources or None,
                            comment=f"firewalld:{zone_name}:service:{svc}",
                        ).with_rule_id()
                    )

            # ---------------------------------------------------------
            # 3. NAT: masquerade
            # ---------------------------------------------------------
            if z.get("masquerade"):
                rules.append(
                    Rule(
                        family="inet",
                        table="nat",
                        chain="POSTROUTING",
                        action="masquerade",
                        interface=interfaces or None,
                        comment=f"firewalld:{zone_name}:masquerade",
                    ).with_rule_id()
                )

            # ---------------------------------------------------------
            # 4. NAT: forward (firewalld forward=1)
            # ---------------------------------------------------------
            if z.get("forward"):
                rules.append(
                    Rule(
                        family="inet",
                        table="filter",
                        chain="FORWARD",
                        action="accept",
                        interface=interfaces or None,
                        comment=f"firewalld:{zone_name}:forward",
                    ).with_rule_id()
                )

            # ---------------------------------------------------------
            # 5. Trusted / botblock (if present)
            # ---------------------------------------------------------
            if z.get("trusted"):
                rules.append(
                    Rule(
                        family="inet",
                        table="filter",
                        chain="INPUT",
                        action="accept",
                        src="trusted",
                        comment=f"firewalld:{zone_name}:trusted",
                    ).with_rule_id()
                )

            if z.get("botblock"):
                rules.append(
                    Rule(
                        family="inet",
                        table="filter",
                        chain="INPUT",
                        action="drop",
                        src="botblock",
                        comment=f"firewalld:{zone_name}:botblock",
                    ).with_rule_id()
                )

            # ---------------------------------------------------------
            # 6. Rich rules (if present)
            # ---------------------------------------------------------
            for rr in z.get("rich_rules", []):
                rr_rule = self._rich_rule_to_rule(rr, zone_name, interfaces, sources)
                if rr_rule:
                    rules.append(rr_rule.with_rule_id())

        return rules

    def _rules_from_nft(self, nft: dict) -> list[Rule]:
        """
        Convert nftables kernel state (as parsed JSON) into canonical Rule objects.

        Only extracts rules from:
            - family = "inet"
            - table = "firewalld"

        Handles:
            - protocol matches
            - ports (sport/dport)
            - addresses (src/dst)
            - interfaces (iif/oif)
            - verdicts (accept/drop/reject/jump/etc.)
        """

        rules: list[Rule] = []

        nft_list = nft.get("nftables", [])
        if not isinstance(nft_list, list):
            return rules

        for entry in nft_list:
            chain = entry.get("chain")
            if not chain:
                continue

            # Only consider inet/firewalld rules
            if chain.get("family") != "inet":
                continue
            if chain.get("table") != "firewalld":
                continue

            chain_name = chain.get("name")
            if not chain_name:
                continue

            # Iterate rules inside this chain
            for raw_rule in chain.get("rules", []):
                rule = self._nft_raw_to_rule(raw_rule, chain_name)
                if rule:
                    rules.append(rule.with_rule_id())

        return rules
    
    def _rules_from_nft(self, nft: dict) -> list[Rule]:
        """
        Convert nftables kernel state (as parsed JSON) into canonical Rule objects.

        Only extracts rules from:
            - family = "inet"
            - table = "firewalld"

        Handles:
            - protocol matches
            - ports (sport/dport)
            - addresses (src/dst)
            - interfaces (iif/oif)
            - verdicts (accept/drop/reject/jump/etc.)
        """

        rules: list[Rule] = []

        nft_list = nft.get("nftables", [])
        if not isinstance(nft_list, list):
            return rules

        for entry in nft_list:
            chain = entry.get("chain")
            if not chain:
                continue

            # Only consider inet/firewalld rules
            if chain.get("family") != "inet":
                continue
            if chain.get("table") != "firewalld":
                continue

            chain_name = chain.get("name")
            if not chain_name:
                continue

            # Iterate rules inside this chain
            for raw_rule in chain.get("rules", []):
                rule = self._nft_raw_to_rule(raw_rule, chain_name)
                if rule:
                    rules.append(rule.with_rule_id())

        return rules    
        
    def _map_firewalld_action(self, raw: dict) -> str:
        """
        Map firewalld/nftables rule JSON to a canonical action string.
        Firewalld often omits explicit verdicts; those default to 'accept'.
        """

        # 1. If nftables JSON includes a verdict expression
        verdict = raw.get("verdict")
        if verdict:
            # nftables verdicts look like: {"type": "accept"} or {"type": "jump", "target": "XYZ"}
            vtype = verdict.get("type")

            if vtype in ("accept", "drop", "reject", "return", "continue"):
                return vtype

            if vtype == "jump":
                return "jump"

            # Unknown verdict type — preserve but log
            self.logger.debug(f"[FIREWALLD] Unknown verdict type: {vtype}")
            return vtype

        # 2. No verdict → implicit accept (firewalld default)
        return "accept"

    def _rich_rule_to_rule(self, rr: dict, zone_name: str,
                        interfaces: list[str] | None,
                        sources: list[str] | None) -> Rule | None:
        """
        Convert a firewalld rich rule (already parsed) into a canonical Rule.

        Expected structure (simplified):
            {
                "family": "ipv4" | "ipv6" | None,
                "source": {"address": "..."} | None,
                "destination": {"address": "..."} | None,
                "service": {"name": "..."} | None,
                "port": {"port": "80", "protocol": "tcp"} | None,
                "protocol": {"value": "tcp"} | None,
                "log": {...} | None,
                "action": {"type": "accept" | "drop" | "reject"} | None
            }

        Firewalld rich rules are always "filter" table rules.
        """

        if not isinstance(rr, dict):
            return None

        # ---------------------------------------------------------
        # 1. Extract action
        # ---------------------------------------------------------
        action = None
        if "action" in rr and isinstance(rr["action"], dict):
            action = rr["action"].get("type")

        if not action:
            # firewalld defaults to accept if no action is specified
            action = "accept"

        # ---------------------------------------------------------
        # 2. Extract protocol
        # ---------------------------------------------------------
        proto = None
        if "protocol" in rr and isinstance(rr["protocol"], dict):
            proto = rr["protocol"].get("value")

        # ---------------------------------------------------------
        # 3. Extract port or service
        # ---------------------------------------------------------
        sport = None
        dport = None

        # Port rule
        if "port" in rr and isinstance(rr["port"], dict):
            p = rr["port"]
            dport = int(p.get("port")) if p.get("port") else None
            proto = proto or p.get("protocol")

        # Service rule
        if "service" in rr and isinstance(rr["service"], dict):
            svc = rr["service"].get("name")
            mapping = self.service_port_map.get(svc)
            if mapping:
                dport = int(mapping.get("port"))
                proto = proto or mapping.get("proto", [None])[0]

        # ---------------------------------------------------------
        # 4. Extract source/destination
        # ---------------------------------------------------------
        src = None
        dst = None

        if "source" in rr and isinstance(rr["source"], dict):
            src = rr["source"].get("address")

        if "destination" in rr and isinstance(rr["destination"], dict):
            dst = rr["destination"].get("address")

        # ---------------------------------------------------------
        # 5. Interfaces (zone-level)
        # ---------------------------------------------------------
        iface = interfaces or None

        # ---------------------------------------------------------
        # 6. Build Rule
        # ---------------------------------------------------------
        return Rule(
            family="inet",
            table="filter",
            chain="INPUT",
            protocol=proto,
            sport=sport,
            dport=dport,
            src=src or (sources or None),
            dst=dst,
            interface=iface,
            action=action,
            comment=f"firewalld:{zone_name}:rich",
        )

