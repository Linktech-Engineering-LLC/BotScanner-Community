"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-25
Modified: 2026-01-23
File: BotScanner/loggers/factory.py
Description: Implements Logging and provides a clean way to retrieve namespace loggers.
"""
#system imports
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
# Project imports
from ..utils.common import parse_size
from .handlers import ArchiveRotatingFileHandler
from .logger import Logger

class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[36m",   # Cyan
        logging.INFO: "\033[32m",    # Green
        logging.WARNING: "\033[33m", # Yellow
        logging.ERROR: "\033[31m",   # Red
        logging.CRITICAL: "\033[41m" # Red background
    }
    RESET = "\033[0m"

    def format(self, record):
        base_msg = super().format(record)
        color = self.COLORS.get(record.levelno, "")
        return f"{color}{base_msg}{self.RESET}" if color else base_msg

class LoggerFactory:
    def __init__(self, log_cfg: dict, project_name: str):
        self.project_name = project_name
        self.log_cfg = log_cfg

        # Use configured path or fallback
        self.log_path = Path(
            log_cfg.get("path", Path.cwd() / "Logs" / f"{project_name}.log")
        )

        # Ensure directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Configure root logger once
        self._configure_root_logger()

    def _configure_root_logger(self):
        root_logger = logging.getLogger(self.project_name)

        # Use configured level or default to INFO
        level_name = self.log_cfg.get("log_level", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)
        root_logger.setLevel(level)

        root_logger.handlers.clear()

        archive_mode = self.log_cfg.get("mode", "tgz").lower()
        backup_count = self.log_cfg.get("backup_count", 5)
        max_bytes = parse_size(self.log_cfg.get("max_size", "10MB"))

        if self.log_cfg.get("rotate_logs", True) and self.log_cfg.get("archive", True):
            file_handler = ArchiveRotatingFileHandler(
                self.log_path,
                mode=archive_mode,
                maxBytes=max_bytes,
                backupCount=backup_count,
            )
        else:
            # plain rotating file handler
            file_handler = RotatingFileHandler(
                self.log_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
            )

        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        file_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(file_handler)
        if self.log_cfg.get("console", True):
            stream_handler = logging.StreamHandler()
            if self.log_cfg.get("color", False):
                stream_handler.setFormatter(ColorFormatter("[%(levelname)s] %(name)s: %(message)s"))
                root_logger.info("[LoggerFactory] Console color enabled via logging.color")
            else:
                stream_handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
                root_logger.info("[LoggerFactory] Console color disabled")
            stream_handler.setLevel(logging.INFO)
            root_logger.addHandler(stream_handler)

    def get_logger(self, module: str = None) -> logging.Logger:
        if module:
            base_logger = logging.getLogger(f"{self.project_name}.{module}")
        else:
            base_logger = logging.getLogger(self.project_name)

        #logger.propagate = True
        return Logger(
            base=base_logger,
            module=module,
        )

    def get_logger_cfg(self) -> dict:
            """Return the logging configuration used to create this factory."""
            return self.log_cfg
    
 
