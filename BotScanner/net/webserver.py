"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-31
Modified: 2026-01-05
File: BotScanner/net/webserver.py
Description: Describe the purpose of this file
"""
# System Libraries
# Project Libraries
from .net_tools import local_command
from .server import Server

class WebServer(Server):
    def check_status(self):
        super().check_status()

        if self.config.get("enforcement", {}).get("check_ports", False):
            self._check_ports()

    def _check_ports(self):
        ports_cfg = self.config.get("ports", [])
        for entry in ports_cfg:
            port = entry.get("port")
            proto = entry.get("protocol", "tcp")
            required = entry.get("required", False)
            enabled = entry.get("enabled", False)

            # Derive actual state from system (ss/netstat/lsof)
            actual_state = self._is_port_listening(port, proto)

            if required and not actual_state:
                self.logger.error(f"[WebServer] Required port {port}/{proto} is NOT listening")
            elif enabled and actual_state:
                self.logger.info(f"[WebServer] Port {port}/{proto} is enabled and listening")
            else:
                self.logger.warning(f"[WebServer] Port {port}/{proto} state mismatch (cfg enabled={enabled}, actual={actual_state})")

    def _is_port_listening(self, port, proto):
        # Example: use `ss -ltn` or `netstat -plnt`
        cmd = f"ss -ltn sport = :{port}"
        result = local_command(cmd)
        return result.code == 0 and str(port) in result.msg