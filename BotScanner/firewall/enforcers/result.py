"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-17
Modified: 2026-03-13
File: BotScanner/firewall/enforcers/result.py
Description: Describe the purpose of this file
"""

# System Libraries
from dataclasses import dataclass, field
from typing import List, Dict, Any
# Project Libraries


@dataclass
class EnforcementResult:
    ok: bool = True
    status: str = "PENDING"
    details: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add_error(self, msg: str):
        self.ok = False
        self.status = "ERROR"
        self.errors.append(msg)

    def merge(self, other: "EnforcementResult"):
        # Merge details counters
        for k, v in other.details.items():
            self.details[k] = self.details.get(k, 0) + v

        # Merge errors
        self.errors.extend(other.errors)

        # Update status
        if other.status == "ERROR":
            self.ok = False
            self.status = "ERROR"
        elif other.status == "CHANGED" and self.status != "ERROR":
            self.status = "CHANGED"
