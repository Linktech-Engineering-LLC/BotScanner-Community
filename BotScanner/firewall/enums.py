"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-03-13
Modified: 2026-03-13
File: BotScanner/firewall/enums.py
Description: Describe the purpose of this file
"""

# System Libraries
from enum import Enum, auto
# Project Libraries

class LifecycleState(Enum):
    BOOTSTRAP = auto()   # No baseline, no nxt, no live
    BASELINE = auto()    # Baseline exists
    NXT = auto()         # NXT exists
    LIVE = auto()        # Live rules detected
    UNKNOWN = auto()     # Fallback

class ReleaseClass(Enum):
    DEV = "DEV"
    COM = "COM"
    PRO = "PRO"
    ENT = "ENT"

