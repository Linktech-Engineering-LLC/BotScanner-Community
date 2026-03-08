"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-26
Modified: 2026-01-05
File: BotScanner/errors.py
Description: Domain-Specific Error Handling Classes and functions
"""


class ConfigError(Exception):
    """Raised when BotScanner fails to load or validate configuration."""
    pass
