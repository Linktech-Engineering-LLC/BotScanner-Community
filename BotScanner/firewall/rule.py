"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-26
Modified: 2026-02-03
File: BotScanner/firewall/rule.py
Description: Describe the purpose of this file
"""
# System Libraries
import hashlib
import json
from dataclasses import dataclass, asdict, field
from typing import Optional, Union, List, Dict, Any, Tuple
# Project Libraries

# --- Field / Rule models (adapt names if yours differ) ------------------------

@dataclass(frozen=True)
class Field:
    family: str                  # "ip", "ip6", "inet" (for src/dst)
    key: str                     # "saddr", "daddr", "sport", "dport"
    is_set: bool = False
    ref_name: Optional[str] = None
    value: Optional[Union[str, List[str], Tuple[str, str]]] = None


@dataclass(frozen=True)
class Rule:
    # Core identity
    family: Optional[str] = None
    table: Optional[str] = None
    chain: Optional[str] = None

    # v3 zone-centric fields
    src_zone: Optional[str] = None
    dst_zone: Optional[str] = None

    # Future raw-IP / service fields
    src: Optional[str] = None
    dst: Optional[str] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    proto: Optional[str] = None
    interface: Optional[str] = None

    # Action / verdict
    action: str = "accept"
    counter: bool = False

    # Metadata
    comment: Optional[str] = None
    rule_id: Optional[str] = None

    # raw activation / semantic payload (for backend expression building)
    raw: Optional[Dict[str, Any]] = field(default=None, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        raw = asdict(self)
        return {k: raw[k] for k in sorted(raw.keys())}

    def sort_key(self):
        return (
            self.family or "",
            self.table or "",
            self.chain or "",
            self.src_zone or "",
            self.dst_zone or "",
            self.proto or "",
            self.dport or -1,
            self.sport or -1,
            self.src or "",
            self.dst or "",
            self.interface or "",
            self.action or "",
            self.comment or "",
            self.rule_id or "",
        )

    def identity_key(self) -> Tuple:
        """
        Canonical identity key for v3 rules.
        Only semantic fields are included.
        """
        return (
            self.family or None,
            self.table or None,
            self.chain or None,
            self.src_zone or None,
            self.dst_zone or None,
            self.action or None,
        )

    def with_rule_id(self) -> "Rule":
        canonical = self.to_dict()
        canonical_no_id = {k: v for k, v in canonical.items() if k != "rule_id"}

        payload = json.dumps(
            canonical_no_id,
            sort_keys=True,
            separators=(",", ":"),
        )

        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        rule_id = f"sha256:{digest}"

        return Rule(**{**canonical_no_id, "rule_id": rule_id})


                    