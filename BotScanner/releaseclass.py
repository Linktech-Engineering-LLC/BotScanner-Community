"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-17
Modified: 2026-02-17
File: BotScanner/releaseclass.py
Description: Describe the purpose of this file
"""

# System Libraries
from enum import Enum
# Project Libraries

class ReleaseClass(Enum):
    DEV = "DEV"      # Full access, destructive rebuild allowed
    COM = "COM"      # Community Edition, safe non-destructive behavior
    PRO = "PRO"      # Professional Edition, advanced features
    ENT = "ENT"      # Enterprise Edition, full capabilities