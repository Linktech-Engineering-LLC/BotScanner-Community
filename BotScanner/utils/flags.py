"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-26
Modified: 2026-01-05
File: BotScanner/utils/flags.py
Description: Obtains the flags from the configuration converts to a bitmap
"""

# System Libraries
from enum import IntFlag

class Flags:
    FLAG_NAMES = [
        # Core modes
        "ROOT_MODE", "CI_MODE", "CRON_MODE", "VERBOSE", "ENABLE_DRY_RUN"
        # Logging / reporting
        "ENABLE_LOGGING", "ENABLE_SUMMARY",
        "EXPORT_JSON", "EXPORT_HTML", "INCLUDE_PYTHON_VERSION",
        # Firewall
        "FIREWALL_BASE", "FIREWALL_STATUS", "FIREWALL_DRIFT",
        "IPSET_MODE", "CROSS_DRIFT", "ENABLE_NFT",
        # Enforcement
        "ENFORCE_MANAGER", "ENFORCE_KERNEL",
        # Server checks
        "SERVER_STATUS", "SERVER_LOG_SCAN", "SERVER_DEEP"
    ]
    GROUPS = {
        "core": [
            "ROOT_MODE",
            "CI_MODE",
            "CRON_MODE",
            "VERBOSE",
            "ENABLE_DRY_RUN",
        ],
        "logging":[
            "ENABLE_LOGGING",
            "ENABLE_SUMMARY",
            "EXPORT_JSON",
            "EXPORT_HTML",
            "INCLUDE_PYTHON_VERSION",
        ],
        "firewall": [
            "FIREWALL_BASE",
            "FIREWALL_STATUS",
            "FIREWALL_DRIFT",
            "IPSET_MODE",
            "CROSS_DRIFT",
            "ENABLE_NFT",
        ],
        "enforcement": [
            "ENFORCE_MANAGER",
            "ENFORCE_KERNEL",
        ],
        "servers": [
            "SERVER_STATUS",
            "SERVER_LOG_SCAN",
            "SERVER_DEEP",
        ]
    }

    DEVELOPMENT_MODE = True  # flip to False for release builds

    # Build IntFlag dynamically
    _members = {name: 1 << idx for idx, name in enumerate(FLAG_NAMES)}
    BitmapFlags = IntFlag("BitmapFlags", _members)

    def __init__(self, mask: int = 0):
        self.mask = self.BitmapFlags(mask)

    @classmethod
    def from_config(cls, cfg: dict):
        flags_section = cfg.get("flags", {})
        custom_flags = flags_section.get("custom_flags", {}) if cls.DEVELOPMENT_MODE else {}

        all_names = cls.FLAG_NAMES + list(custom_flags.keys())

        bits = 0
        for idx, name in enumerate(all_names):
            if flags_section.get(name, False) or custom_flags.get(name, False):
                bits |= (1 << idx)
        return bits

    @classmethod
    def from_dict(cls, flags_dict: dict):
        """
        Convert a dict of flag_name: bool into a BitmapFlags instance.
        """
        mask = 0
        for name, enabled in flags_dict.items():
            if enabled:
                member = getattr(cls.BitmapFlags, name, None)
                if member is not None:
                    mask |= member
        return cls.BitmapFlags(mask)

    @classmethod
    def from_mask(cls, mask: int):
        """Return a BitmapFlags instance from an integer mask."""
        return cls.BitmapFlags(mask)

    def to_dict(self) -> dict[str, bool]:
        return {
            name: bool(self.value & getattr(Flags.BitmapFlags, name))
            for name in Flags.FLAG_NAMES
        }

    def active_names(self):
        names = []
        for name in Flags.FLAG_NAMES:
            member = getattr(Flags.BitmapFlags, name)
            if self & member:
                names.append(name)
        return names

    
    @classmethod
    def names_in_group(cls, group_name):
        """Return list of flag names belonging to a group."""
        return cls.GROUPS.get(group_name, [])
    
    @classmethod
    def active_in_group(cls, group, active_flag_names):
        group_flags = set(cls.GROUPS.get(group, []))
        active = set(active_flag_names)
        return list(group_flags.intersection(active))

    @classmethod
    def active_names_from_mask(cls, mask: int):
        flags = cls.BitmapFlags(mask)
        names = []
        for name in cls.FLAG_NAMES:
            member = getattr(cls.BitmapFlags, name)
            if flags & member:
                names.append(name)
        return names

    @classmethod
    def group_mask(cls, group: str):
        names = cls.GROUPS.get(group, [])
        mask = 0
        for name in names:
            member = getattr(cls.BitmapFlags, name)
            mask |= member
        return cls.BitmapFlags(mask)

    def to_hex(self) -> str:
         return f"0x{self.value:X}"

    def to_mask(self):
        return self.value

    def __str__(self) -> str:
        return f"{self.active_names()} ({self.to_hex()})"

    BitmapFlags.active_names = active_names
    BitmapFlags.to_hex = to_hex
    BitmapFlags.to_dict = to_dict
    BitmapFlags.FLAG_NAMES = FLAG_NAMES
