"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-26
Modified: 2026-01-05
File: BotScanner/context.py
Description: Domain-specific helper classes and functions
"""
# system imports
import socket
import uuid

class BotScannerContext:
    def __init__(self, logger, logger_factory, log_cfg, paths, hosts, args):
        self.logger = logger
        self.logger_factory = logger_factory
        self.log_cfg = logger_factory.get_logger_cfg()
        self.hosts = hosts
        self.args = args

        self.hostname = socket.gethostname().lower()
        self.run_id = None

    def start_run(self, config_hash=None):
        self.run_id = uuid.uuid4().hex[:8]
        logger = self.logger_factory.get_logger("BotScanner.Run")

        if self.log_cfg.get("debug_banner", False):
            logger.info("=== BotScanner cycle start ===")
            logger.info(f"RunID={self.run_id} Host={self.hostname} Config={config_hash or 'N/A'}")
            logger.info("================================")
        else:
            logger.debug("[BotScannerContext] Debug banner suppressed")

    def end_run(self):
        logger = self.logger_factory.get_logger("BotScanner.Run")

        if self.log_cfg.get("debug_banner", False):
            logger.info("=== BotScanner cycle complete ===")
            logger.info(f"RunID={self.run_id} Host={self.hostname} Status=complete")
            logger.info("================================")
        else:
            logger.debug("[BotScannerContext] Debug banner suppressed")