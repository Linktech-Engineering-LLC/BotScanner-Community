"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-17
Modified: 2026-03-13
File: BotScanner/licensemgr.py
Description: Describe the purpose of this file
"""

# System Libraries
import os
# Project Libraries
from .releaseclass import ReleaseClass

class DummyLicense:
    """
    Development-only fallback license.
    Always returns DEV unless overridden.
    """
    def __init__(self, release_class: ReleaseClass = ReleaseClass.DEV):
        self.release_class = release_class
        self.raw = None

class License:
    """
    Simple container for license information.
    """
    def __init__(self, release_class: ReleaseClass, raw: str | None):
        self.release_class = release_class
        self.raw = raw


class LicenseManager:
    """
    Loads and validates the BotScanner license file.
    Determines the release class (DEV/COM/PRO/ENT).
    """

    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.logger = logger

    def load(self) -> License:
        if self.cfg.get("botscanner", {}).get("metadata", {}).get("license_enabled", False) is False:
            self.logger.lifecycle("[LICENSE] License disabled; using DummyLicense")
            return DummyLicense()

        """
        Load the license file and determine the release class.
        Fallback to COM if missing or invalid.
        """
        path = self._license_path()

        if not os.path.exists(path):
            self.logger.lifecycle("[LICENSE] No license found; defaulting to COM")
            return License(ReleaseClass.COM, raw=None)

        try:
            with open(path, "r") as f:
                raw = f.read().strip()
        except Exception as e:
            self.logger.error(f"[LICENSE] Failed to read license file: {e}")
            return DummyLicense()

        release_class = self._determine_class(raw)
        return License(release_class, raw)

    def _license_path(self) -> str:
        """
        Resolve the license file path from cfg.
        """
        try:
            return self.cfg["license"]["path"]
        except Exception:
            # If cfg is missing the license section, default to COM
            self.logger.lifecycle("[LICENSE] No license path in cfg; defaulting to COM")
            return "/etc/botscanner/license.txt"

    def _determine_class(self, raw: str) -> ReleaseClass:
        """
        Determine the release class from the raw license string.
        For now, simple matching. Later: signatures, expiry, metadata.
        """
        token = raw.upper()

        if token in ("DEV", "DEVELOPMENT"):
            return ReleaseClass.DEV

        if token in ("COM", "COMMUNITY"):
            return ReleaseClass.COM

        if token in ("PRO", "PROFESSIONAL"):
            return ReleaseClass.PRO

        if token in ("ENT", "ENTERPRISE"):
            return ReleaseClass.ENT

        self.logger.lifecycle(f"[LICENSE] Unknown license token '{raw}', defaulting to COM")
        return ReleaseClass.COM