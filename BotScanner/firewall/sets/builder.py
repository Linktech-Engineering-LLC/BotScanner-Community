"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-09
Modified: 2026-02-11
File: BotScanner/firewall/sets/builder.py
Description:
    YAML → Elements → Normalized Element List

    This module is responsible for:
    - Loading YAML-defined elements for each set
    - Normalizing IPv4/IPv6 addresses
    - Applying timeouts (if present)
    - Merging YAML elements with activation-derived elements
    - Producing a deterministic, backend-agnostic element list

    NOTE:
    This module does NOT:
    - Perform backend operations (nft, iptables, firewalld)
    - Perform interface/zone activation (handled by enforcers/builder.py)
    - Generate rules (handled by ruleset.py)
    - Enforce rules (handled by enforcers/)
"""

# System Libraries
import ipaddress
# Project Libraries
# Local Libraries


class SetElementBuilder:
    """
    SetElementBuilder
    -----------------
    Converts YAML-defined elements + activation-derived elements
    into a normalized, deterministic element list.

    Output format:
        {
            "trusted": [
                {"addr": "192.168.0.86/32", "timeout": None},
                {"addr": "192.168.0.0/24", "timeout": None},
            ],
            "public": [...],
            ...
        }
    """

    def __init__(self, cfg: dict, activation_map: dict, logger):
        """
        cfg: full BotScanner config dict
        activation_map: output of ActivationMapBuilder.build()
        logger: logger instance
        """
        self.cfg = cfg
        self.activation_map = activation_map
        self.logger = logger

    # ------------------------------------------------------------------
    # PUBLIC ENTRYPOINT
    # ------------------------------------------------------------------
    def build(self) -> dict:
        """
        Build final element lists for each set.

        Steps:
        1. Load YAML-defined elements
        2. Load activation-derived elements
        3. Normalize addresses
        4. Merge + deduplicate
        5. Sort deterministically
        """
        firewall_cfg = self.cfg.get("firewall", {})
        sets_cfg = firewall_cfg.get("sets", [])

        final_sets = {}

        for set_cfg in sorted(sets_cfg, key=lambda s: s["name"]):
            name = set_cfg["name"]
            flags = set_cfg.get("flags", [])
            allow_prefix = "interval" in flags
            
            yaml_elements = set_cfg.get("elements", [])
            activation_elements = self.activation_map.get(name, {}).get("elements", [])

            merged = []
            merged.extend(self._normalize_yaml_elements(yaml_elements, allow_prefix))
            merged.extend(self._normalize_activation_elements(activation_elements, allow_prefix))

            # Deduplicate by addr+timeout
            dedup = self._dedupe(merged)

            # Sort deterministically
            dedup = sorted(dedup, key=lambda e: (e["addr"], e.get("timeout") or ""))

            final_sets[name] = dedup

        return final_sets

    # ------------------------------------------------------------------
    # YAML ELEMENTS
    # ------------------------------------------------------------------
    def _normalize_yaml_elements(self, elements, allow_prefix):
        """
        Normalize YAML-defined elements:
        - Ensure CIDR notation
        - Validate IPv4/IPv6
        - Preserve timeout
        """
        normalized = []

        for elem in elements:
            addr = elem.get("addr")
            timeout = elem.get("timeout")

            if not addr:
                continue

            try:
                normalized_addr = self._normalize_addr(addr, allow_prefix)
                normalized.append({"addr": normalized_addr, "timeout": timeout})
            except ValueError:
                self.logger.warning(f"Invalid YAML element address: {addr}")

        return normalized

    # ------------------------------------------------------------------
    # ACTIVATION ELEMENTS
    # ------------------------------------------------------------------
    def _normalize_activation_elements(self, elements, allow_prefix):
        """
        Normalize activation-derived elements:
        - These already come in {"addr": "..."} form
        - No timeout support here
        """
        normalized = []

        for elem in elements:
            addr = elem.get("addr")
            if not addr:
                continue

            try:
                normalized_addr = self._normalize_addr(addr, allow_prefix)

                out = {"addr": normalized_addr}

                timeout = elem.get("timeout")
                if timeout is not None:
                    out["timeout"] = timeout

                normalized.append(out)

            except ValueError:
                self.logger.warning(f"Invalid activation element address: {addr}")

        return normalized

    # ------------------------------------------------------------------
    # ADDRESS NORMALIZATION
    # ------------------------------------------------------------------
    def _normalize_addr(self, addr: str, allow_prefix: bool) -> str:
        """
        Normalize IPv4/IPv6 addresses:
        - Convert bare IPs to /32 or /128
        - Preserve CIDR if present
        """
        try:
            # If it's already CIDR, ip_network will accept it
            net = ipaddress.ip_network(addr, strict=False)
            return str(net) if allow_prefix else str(net.network_address)
        except ValueError:
            # Try bare IP
            try:
                ip = ipaddress.ip_address(addr)
                return str(ip) if not allow_prefix else (
                    f"{addr}/32" if ip.version == 4 else f"{addr}/128"
                )
            except ValueError:
                raise

    # ------------------------------------------------------------------
    # DEDUPLICATION
    # ------------------------------------------------------------------
    def _dedupe(self, elements):
        """
        Deduplicate elements by (addr, timeout)
        """
        seen = set()
        result = []

        for elem in elements:
            key = (elem["addr"], elem.get("timeout"))
            if key not in seen:
                seen.add(key)
                result.append(elem)

        return result
    