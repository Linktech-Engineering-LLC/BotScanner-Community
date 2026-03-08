"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-31
Modified: 2026-01-15
File: BotScanner/loggers/logger.py
Description: Describe the purpose of this file
"""
# System Libraries
import logging
# Project Libraries
from .constants import LIFECYCLE_EVENTS

class Logger:
    def __init__(self, base: logging.Logger, module: str = None):
        self._base = base
        self.module = module

    def audit(self, lifecycle_marker: str, message: str, **context):
        if lifecycle_marker not in LIFECYCLE_EVENTS:
            raise ValueError(f"Invalid lifecycle marker: {lifecycle_marker}")

        formatted = f"[{lifecycle_marker}] {message}"
        if context:
            formatted += f" | context={context}"

        self._base.log(logging.AUDIT, formatted)

    def lifecycle(self, label: str, value: object = None):
        msg = f"{label}={value}" if value is not None else label
        self._base.log(logging.LIFECYCLE, msg)

    # Delegate Standard Logging Methods
    def info(self, msg: str):
        self._base.info(msg)

    def debug(self, msg: str):
        self._base.debug(msg)

    def warning(self, msg: str):
        self._base.warning(msg)

    def error(self, msg: str):
        self._base.error(msg)

    # Lifecycle helpers
    def command_start(self, cmd: str):
        self._base.info(f"CMD_START: {cmd}")

    def command_end(self, cmd: str, code: int):
        self._base.info(f"CMD_END: {cmd} | exit_code={code}")

    def command_error(self, func_name: str, error: Exception):
        self._base.error(
            f"CMD_FAIL: {func_name} | {type(error).__name__} | {str(error)}"
        )

    def banner(self, message: str):
        line = "=" * 60
        self.info(line)
        self.info(f"== {message}")
        self.info(line)
    