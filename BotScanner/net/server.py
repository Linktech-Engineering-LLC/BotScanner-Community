"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-31
Modified: 2026-01-23
File: BotScanner/net/server.py
Description: Describe the purpose of this file
"""
# System Libraries
import socket
# Project Libraries
from ..loggers import LoggerFactory
from .net_tools import sudo_run

class Server:
    def __init__(self, name: str=None, config: dict=None, logger_factory: LoggerFactory = None):
        # Secrets must include sudo_pass
        sudo_pass = config.get("secrets", {}).get("sudo_pass")
        if not sudo_pass:
            raise RuntimeError("sudo_password required for monitoring")
        self.name = name
        self.config = config or {}
        self.sudo_pass = sudo_pass

        # Use YAML host if present, otherwise derive locally
        self.host = config.get("host", socket.gethostname())

        # Pull other sections from master config
        self.server_cfg = config.get("server", {})
        self.inventory = config.get("inventory", {})
        self.ipconfig = config.get("ipconfig", {})
        self.flags = config.get("flags", 0)

        # Use provided factory or create a default one
        if logger_factory is None:
            # Default: INFO level, logs to ./Logs/BotScanner.log
            default_cfg = {"log_level": "INFO"}
            logger_factory = LoggerFactory(default_cfg, project_name="BotScanner")

        self.logger_factory = logger_factory
        self.logger = self.logger_factory.get_logger(module="Server")

        self.logger.info(f"Local Server initialized for host={self.host}")

    def check_status(self):
        """Check status of all configured daemons and enforce restart if needed."""
        services_cfg = self.config.get("services", {})
        commands = services_cfg.get("commands", {})

        # --- check if enabled ---
        enabled_cmd = commands.get("is_enabled_cmd", "").replace("{{ daemons }}", self.name)
        enabled_result = sudo_run(enabled_cmd, self.sudo_pass, self.logger)

        if enabled_result.code != 0 or enabled_result.msg.strip() != "enabled":
            self.logger.warning(f"[STATUS] {self.name} is not enabled (rc={enabled_result.code})")
            return

        # --- check if active ---
        active_cmd = commands.get("is_active_cmd", "").replace("{{ daemons }}", self.name)
        active_result = sudo_run(active_cmd, self.sudo_pass, self.logger)

        if active_result.code == 0 and active_result.msg.strip() == "active":
            self.logger.info(f"[STATUS] {self.name} is enabled and active")
        else:
            # --- restart if inactive ---
            restart_cmd = commands.get("restart_cmd", "").replace("{{ daemons }}", self.name)
            restart_result = sudo_run(restart_cmd, self.sudo_pass, self.logger)

            if restart_result.code == 0:
                self.logger.audit("COMPLETE", f"{self.name} restarted successfully")
            else:
                self.logger.error(f"[STATUS] {self.name} restart failed: {restart_result.err}")

                fallback_cmds = services_cfg.get("daemons", {}).get(self.name, {}).get("fallback", [])
                if fallback_cmds:
                    self.logger.audit("RECREATE", f"{self.name} attempting fallback sequence")

                    for cmd in fallback_cmds:
                        rc = sudo_run(cmd, self.sudo_pass, self.logger)
                        self.logger.audit("CMD_START", f"Executed fallback: {cmd}", rc=rc.code)

                    active_check = sudo_run(f"systemctl is-active {self.name}", self.sudo_pass, self.logger)
                    status = active_check.stdout.strip() if active_check.stdout else ""
                    if status == "active":
                        self.logger.audit("CMD_END", f"{self.name} recovered via fallback")
                    else:
                        self.logger.audit("STATUS", f"{self.name} still inactive after fallback", rc=active_check.code)
                else:
                    self.logger.audit("STATUS", f"{self.name} has no fallback defined")
