"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-17
Modified: 2026-02-17
File: BotScanner/firewall/enforcers/policy.py
Description: Describe the purpose of this file
"""

# System Libraries
from dataclasses import dataclass
# Project Libraries

@dataclass
class EnforcementPolicy:
    # Mode: strict | audit | hybrid
    mode: str

    # Enforcement behavior
    enforce_all: bool
    enforce_critical: bool
    enforce_noncritical: bool

    # Drift behavior
    drift_detect: bool
    drift_classify: bool
    drift_cross: bool

    # Lifecycle behavior
    baseline_update: bool
    nxt_save: bool
    nxt_load: bool