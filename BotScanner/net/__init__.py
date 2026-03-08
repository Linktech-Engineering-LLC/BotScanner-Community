"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-05
Modified: 2026-02-05
File: BotScanner/net/__init__.py
Description: Describe the purpose of this file
"""
# Import curated symbols from submodules
from .net_tools import local_command, sudo_run
# Optional: expose version metadata
__version__ = "0.2.0"
# Explicitly define the public API
__all__ = [
    "get_local_subnets",
    "local_command",
    "sudo_run",
    "__version__",
]
