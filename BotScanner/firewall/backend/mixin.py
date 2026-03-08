"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-26
Modified: 2026-01-29
File: BotScanner/firewall/backend/mixin.py
Description: Describe the purpose of this file
"""
# System Libraries
import json
from typing import Any, Optional
# Project Libraries
from ...net import sudo_run

class NftablesMixin:
    """
    Shared nftables helpers for firewalld and nftables backends.
    This mixin provides raw nftables JSON retrieval and will grow
    to include expression extractors and traversal helpers.
    """

    def _get_nft_json(self) -> dict:
        """
        Retrieve the full nftables ruleset in JSON form.
        Backends using nftables (firewalld, nftables) call this.
        """
        cmd = "nft -j list ruleset"
        result = sudo_run(cmd, self.sudo_password)

        if result.code != 0:
            if hasattr(self, "logger") and self.logger:
                self.logger.error(
                    f"[NFTABLES] Failed to run 'nft -j list ruleset': {result.err}"
                )
            return {}

        try:
            nft_json = json.loads(result.msg)
        except Exception as e:
            if hasattr(self, "logger") and self.logger:
                self.logger.error(f"[NFTABLES] JSON parse error: {e}")
            return {}

        if "nftables" not in nft_json:
            if hasattr(self, "logger") and self.logger:
                self.logger.error("[NFTABLES] Unexpected JSON structure: missing 'nftables'")
            return {}

        return nft_json

    # ---------- small helpers ----------

    def _iter_expr(self, rule: dict):
        """
        Yield each expression dict in a rule.
        nftables JSON usually has: { "rule": { "expr": [ {...}, {...} ] } }
        but firewalld/nftables backends may already pass the inner rule dict.
        """
        exprs = rule.get("expr") or rule.get("rule", {}).get("expr") or []
        for expr in exprs:
            yield expr

    def _find_verdict_expr(self, rule: dict) -> Optional[dict]:
        for expr in self._iter_expr(rule):
            if "accept" in expr or "drop" in expr or "reject" in expr:
                return expr
            if "queue" in expr or "return" in expr:
                return expr
            if "jump" in expr or "goto" in expr:
                return expr
        return None

    def _find_cmp_expr(self, rule: dict, left_key: str) -> Optional[dict]:
        """
        Find a 'cmp' expression where 'left' matches a given key string.
        Example left_key values:
          - 'ip saddr'
          - 'ip daddr'
          - 'ip6 saddr'
          - 'ip6 daddr'
          - 'th dport'
          - 'th sport'
        """
        for expr in self._iter_expr(rule):
            cmp_ = expr.get("cmp")
            if not cmp_:
                continue
            left = cmp_.get("left")
            if isinstance(left, dict) and left.get("payload"):
                # payload-based left, e.g. { "payload": { "protocol": "tcp", "field": "dport" } }
                continue
            if isinstance(left, str) and left == left_key:
                return cmp_
        return None

    def _find_payload_cmp(self, rule: dict, protocol: str, field: str) -> Optional[dict]:
        """
        Find a 'cmp' expression where left is a payload with given protocol/field.
        Example:
          protocol='tcp', field='dport'
          protocol='tcp', field='sport'
        """
        for expr in self._iter_expr(rule):
            cmp_ = expr.get("cmp")
            if not cmp_:
                continue
            left = cmp_.get("left")
            if not isinstance(left, dict):
                continue
            payload = left.get("payload")
            if not payload:
                continue
            if payload.get("protocol") == protocol and payload.get("field") == field:
                return cmp_
        return None

    # ---------- verdict ----------

    def _extract_verdict(self, rule: dict) -> Optional[str]:
        expr = self._find_verdict_expr(rule)
        if not expr:
            return None

        if "accept" in expr:
            return "accept"
        if "drop" in expr:
            return "drop"
        if "reject" in expr:
            return "reject"
        if "queue" in expr:
            return "queue"
        if "return" in expr:
            return "return"
        if "jump" in expr:
            return f"jump:{expr['jump'].get('target')}"
        if "goto" in expr:
            return f"goto:{expr['goto'].get('target')}"

        return None

    # ---------- protocol ----------

    def _extract_proto(self, rule: dict) -> Optional[str]:
        """
        Try to extract L4 protocol (tcp/udp/icmp/...) from meta or payload.
        """
        # meta l4proto
        for expr in self._iter_expr(rule):
            meta = expr.get("meta")
            if not meta:
                continue
            if meta.get("key") == "l4proto":
                cmp_ = expr.get("cmp")
                if cmp_:
                    right = cmp_.get("right")
                    if isinstance(right, str):
                        return right.lower()

        # payload-based protocol (less common, but be defensive)
        for expr in self._iter_expr(rule):
            payload = expr.get("payload")
            if not payload:
                continue
            proto = payload.get("protocol")
            if isinstance(proto, str):
                return proto.lower()

        return None

    # ---------- ports ----------

    def _extract_dport(self, rule: dict) -> Optional[str]:
        """
        Extract destination port or port range as string.
        """
        # payload-based (preferred)
        cmp_ = self._find_payload_cmp(rule, protocol="tcp", field="dport") \
               or self._find_payload_cmp(rule, protocol="udp", field="dport")
        if not cmp_:
            # fallback: th dport
            cmp_ = self._find_cmp_expr(rule, "th dport")
        if not cmp_:
            return None

        right = cmp_.get("right")
        return self._normalize_port_value(right)

    def _extract_sport(self, rule: dict) -> Optional[str]:
        """
        Extract source port or port range as string.
        """
        cmp_ = self._find_payload_cmp(rule, protocol="tcp", field="sport") \
               or self._find_payload_cmp(rule, protocol="udp", field="sport")
        if not cmp_:
            cmp_ = self._find_cmp_expr(rule, "th sport")
        if not cmp_:
            return None

        right = cmp_.get("right")
        return self._normalize_port_value(right)

    def _normalize_port_value(self, right: Any) -> Optional[str]:
        """
        Normalize nftables 'right' value for ports into a string.
        Handles:
          - single int
          - list [start, end]
        """
        if isinstance(right, int):
            return str(right)
        if isinstance(right, list) and len(right) == 2:
            return f"{right[0]}-{right[1]}"
        return None

    # ---------- addresses ----------

    def _extract_saddr(self, rule: dict) -> Optional[str]:
        """
        Extract source address (IPv4 or IPv6).
        """
        # ip saddr / ip6 saddr
        cmp_ = self._find_cmp_expr(rule, "ip saddr") or self._find_cmp_expr(rule, "ip6 saddr")
        if not cmp_:
            return None
        return self._normalize_addr_value(cmp_.get("right"))

    def _extract_daddr(self, rule: dict) -> Optional[str]:
        """
        Extract destination address (IPv4 or IPv6).
        """
        cmp_ = self._find_cmp_expr(rule, "ip daddr") or self._find_cmp_expr(rule, "ip6 daddr")
        if not cmp_:
            return None
        return self._normalize_addr_value(cmp_.get("right"))

    def _normalize_addr_value(self, right: Any) -> Optional[str]:
        """
        Normalize nftables 'right' value for addresses into a string.
        Handles:
          - single string
          - list of strings (we return comma-separated for now)
        """
        if isinstance(right, str):
            return right
        if isinstance(right, list) and right and all(isinstance(x, str) for x in right):
            return ",".join(right)
        return None

    # ---------- interfaces ----------

    def _extract_iif(self, rule: dict) -> Optional[str]:
        """
        Extract input interface name (iifname).
        """
        for expr in self._iter_expr(rule):
            meta = expr.get("meta")
            if not meta:
                continue
            if meta.get("key") != "iifname":
                continue
            cmp_ = expr.get("cmp")
            if not cmp_:
                continue
            right = cmp_.get("right")
            if isinstance(right, str):
                return right
        return None

    def _extract_oif(self, rule: dict) -> Optional[str]:
        """
        Extract output interface name (oifname).
        """
        for expr in self._iter_expr(rule):
            meta = expr.get("meta")
            if not meta:
                continue
            if meta.get("key") != "oifname":
                continue
            cmp_ = expr.get("cmp")
            if not cmp_:
                continue
            right = cmp_.get("right")
            if isinstance(right, str):
                return right
        return None

    def _extract_nat_type(self, rule):
        for expr in rule.get("expr", []):
            if "dnat" in expr:
                return "dnat"
            if "snat" in expr:
                return "snat"
            if "masquerade" in expr:
                return "masquerade"
        return None

    def _extract_to_addr(self, rule):
        for expr in rule.get("expr", []):
            if "dnat" in expr:
                return expr["dnat"].get("addr")
            if "snat" in expr:
                return expr["snat"].get("addr")
        return None

    def _extract_to_port(self, rule):
        for expr in rule.get("expr", []):
            if "dnat" in expr:
                return expr["dnat"].get("port")
            if "snat" in expr:
                return expr["snat"].get("port")
        return None
