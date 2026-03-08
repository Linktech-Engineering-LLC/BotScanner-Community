"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-25
Modified: 2026-01-05
File: BotScanner/loggers/handlers.py
Description: A group of log handler classes
"""
# system imports
import os
import logging
import time
import tarfile
import zipfile
import glob
from logging.handlers import RotatingFileHandler
# Project imports

class ArchiveRotatingFileHandler(RotatingFileHandler):
    def __init__(self, filename: str, mode: str="tgz", *args, **kwargs):
        super().__init__(filename, *args, **kwargs)
        self.archive_mode = mode

    def doRollover(self):
        super().doRollover()

        rotated_file = f"{self.baseFilename}.1"
        if os.path.exists(rotated_file):
            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")

            if self.archive_mode == "tgz":
                archive_name = f"{self.baseFilename}.{timestamp}.tgz"
                with tarfile.open(archive_name, "w:gz") as tar:
                    tar.add(rotated_file, arcname=os.path.basename(rotated_file))

            elif self.archive_mode == "zip":
                archive_name = f"{self.baseFilename}.{timestamp}.zip"
                with zipfile.ZipFile(archive_name, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(rotated_file, arcname=os.path.basename(rotated_file))

            else:
                # no archive, just keep rotated_file
                archive_name = rotated_file

            os.remove(rotated_file)

            # enforce backup count
            archives = sorted(
                glob.glob(f"{self.baseFilename}.*.{self.archive_mode}"),
                key=os.path.getmtime,
            )
            if len(archives) > self.backupCount:
                for old_archive in archives[: -self.backupCount]:
                    os.remove(old_archive)

        # reopen new log file
        self.stream = self._open()

        logging.getLogger("BotScanner.Logger").info(
            f"Log rotated: archived {rotated_file} ? {archive_name}"
        )