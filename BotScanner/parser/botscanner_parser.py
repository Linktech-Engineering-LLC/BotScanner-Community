"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-25
Modified: 2026-01-23
File: BotScanner/parser/botscanner_parser.py
Description: CLI parser for BotScanner v2
"""
# system imports
import argparse
import sys
import platform
# project imports
from ..utils.common import read_project_file

# helper constants and functions
project_name = read_project_file("project.name")
project_version = read_project_file("project.version")
linux_version = platform.release()

description = f"{project_name} {project_version} (Linux {linux_version})"
description += f" (Python {sys.version.split()[0]})"

class CustomFormatter(argparse.HelpFormatter):
    """Custom help formatter for BotScanner CLI."""
    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)
        return ', '.join(action.option_strings) + (
            ' ' + self._format_args(action, action.dest) if action.nargs != 0 else ''
        )

class ScriptParser:
    """
    CLI parser for BotScanner v2.
    Responsibilities:
        - Parse core CLI arguments
        - Get path to configuration file
        - Capture vault password (string or file path)
        - Capture server keys/info
        - Host detection deferred until enforcement
    """
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog="BotScanner",
            description=description,
            formatter_class=CustomFormatter
        )
        self._add_core_args()

    def _add_core_args(self):
        self.parser.add_argument(
            "--debug", "-d",
            action="store_true",
            help="Enable debug logging (overrides configuration)"
        )
        self.parser.add_argument(
            "--no-console",
            action="store_true",
            help="Disable console logging output"
        )
        self.parser.add_argument(
            "--verbose", "-v",
            action="store_true",
            help="Enable verbose logging output"
        )
        self.parser.add_argument(
            "--dry-run", "-n",
            action="store_true",
            help="Perform a trial run with no changes made"
        )
        self.parser.add_argument(
            "--vault",
            help="Vault override in format: 'pwd=PATH_OR_STRING,vault=PATH,key=STRING'"
        )


    def parse(self, argv=None):
        args = self.parser.parse_args(argv)
        return args

def parse_vault_arg(arg: str) -> dict:
    """
    Normalize vault argument into a dictionary.
    Format: "pwd=PATH_OR_STRING,vault=PATH,key=STRING"
    """
    parts = arg.split(",")
    kv_pairs = dict(p.split("=", 1) for p in parts)

    required = {"pwd", "vault", "key"}
    if not required.issubset(kv_pairs.keys()):
        raise ValueError(
            f"Invalid vault argument: {arg}. Must contain pwd=..., vault=..., key=..."
        )
    return {
        "password_candidate": kv_pairs["pwd"],
        "vault_path": kv_pairs["vault"],
        "key": kv_pairs["key"],
    }