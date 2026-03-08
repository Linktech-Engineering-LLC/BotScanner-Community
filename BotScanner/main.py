"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-24
Modified: 2026-01-21
File: BotScanner/main.py
Description: The BotScanner package is designed to scan and manage bot-related configurations in a network environment.
"""
# system imports
import sys
import logging
# project imports
from .firewall.orchestrator import FirewallOrchestrator
from .loader import ConfigLoader, ConfigResolver, VaultLoader
from .loggers.log_helpers import (
    init_logger, register_custom_levels
)
from .loggers.constants import LifecycleEvents
from .net.server import Server
from .parser import ScriptParser
from .utils.common import read_project_file
from .utils import Flags
# --- Root logger setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        # logging.FileHandler("botscanner.log")  # optional file output
    ]
)
# Overrides
def apply_overrides(resolved_cfg: dict, overrides: dict) -> dict:
    """
    Apply CLI/env overrides to resolved config.
    Priority: overrides > resolved_cfg.
    """
    for section, values in overrides.items():
        if section not in resolved_cfg:
            resolved_cfg[section] = {}
        if isinstance(values, dict):
            resolved_cfg[section].update(values)
        else:
            resolved_cfg[section] = values
    return resolved_cfg
# Load yaml Configuration Files
def load_config(context: dict=None, config_dir: str=None):
    if "project_name" not in (context or {}):
        context = context or {}
        context["project_name"] = read_project_file("project.name")
    # 1. Load raw config
    loader = ConfigLoader(context=context, config_dir=config_dir)
    cfg = loader.merged

    # 2. Process vault if configured
    secrets = {}
    if "vault" in cfg:
        vault_cfg = cfg["vault"]
        vault_loader = VaultLoader(vault_cfg)
        secrets = vault_loader.load()  # filtered to vault_cfg["key"], e.g. "all"

        # Inject secrets into context for placeholder resolution
        context = context or {}
        context["vault"] = secrets

    # 3. Merge cfg + context for placeholder resolution
    resolver = ConfigResolver(cfg, secrets)
    resolved_cfg = resolver.resolve()

    # 4. Expose secrets explicitly in resolved config
    resolved_cfg["secrets"] = secrets
    return resolved_cfg
# Parse the command line arguments
def get_arguments(context=None, logger=None, flags=0):
    """
    Wrapper for ScriptParser to return CLI arguments.

    Args:
        argv: optional list of CLI arguments (defaults to sys.argv[1:])
        logger: optional logger instance
        flags: optional parser flags (e.g., BitmapFlags.VERBOSE)

    Returns:
        argparse.Namespace with fields:
            - ansible: raw string (normalized later in config loader)
            - debug: bool
            - verbose: bool
            - no_console: bool
            - dry_run: bool
            - vault: dict (if provided via CLI)
    """
    parser = ScriptParser()
    args = parser.parse()
    # 3. Build overrides from CLI args
    overrides = {}
    if args.debug:
        overrides.setdefault("logging", {})["level"] = "DEBUG"
    if args.verbose:
        overrides.setdefault("logging", {})["verbose"] = True
    if args.no_console:
        overrides.setdefault("logging", {})["console"] = False
    if args.dry_run:
        overrides["runtime"] = {"dry_run": True}
    if args.vault:
        overrides["vault"] = args.vault
    # 4. Apply overrides
    updated_context = apply_overrides(context, overrides)
    if logger:
        logger.debug(f"[CLI] Parsed arguments: {args}")

    return updated_context
# Initialize the Logger and Flags
def initialize_logger(context: dict) -> dict:
    """
    Initialize BotScanner runtime loader:
    - Logging system
    - Flags normalization
    - Paths/config metadata
    Returns a unified context dict.
    """
    # Logging setup
    paths, log_cfg, logger_factory = init_logger(
        context,
        console_override=(not context.get("no_console", False))
    )
    register_custom_levels(log_cfg)
    logger = logger_factory.get_logger("loader")
    logger.audit(LifecycleEvents.CONFIG_RESOLVED, "Logger initialized successfully")
    logger.lifecycle(LifecycleEvents.LOADER_SETUP, "Loader Setup Complete")

    # Flags setup
    bot_flags = (
        context.get("applications", {})
               .get("BotScanner", {})
               .get("flags", {})
               .copy()
    )
    if context.get("verbose", False):
        bot_flags["VERBOSE"] = True
    if context.get("dry_run", False):
        bot_flags["ENABLE_DRY_RUN"] = True
 
    flags = Flags.from_dict(context.get("flags", {}))
 
    #flags = Flags.from_dict(bot_flags)

    logger.info(f"Flags initialized: {flags.active_names()} with mask {flags.to_hex()}")

    # Unified loader context
    return {
        "factory": logger_factory,
        "logger": logger,
        "config": log_cfg,
        "paths": paths,
        "flags": flags.to_dict(),       # dict of all flags with True/False
        "active_flags": flags.active_names(),  # list of enabled flag names
        "flags_mask": flags.to_hex(),   # optional: hex bitmask for audits
    }
# Check Server Status
def run_server_status(log: dict, cfg: dict):
    logger_factory = log.get("factory")
    logger = logger_factory.get_logger(module="server")
    logger.lifecycle("[SERVER] Basic status check triggered")
    daemons_cfg = cfg.get("services", {}).get("daemons", {})
    for name, daemon_cfg in daemons_cfg.items():
        if not daemon_cfg.get("check", False):
            logger.info(f"[STATUS] Skipping {name} (check=false)")
            continue

        server = Server(name=name, config=cfg, logger_factory=logger_factory)
        server.check_status()
# Full audit of Servers
def run_server_deep(log: dict, cfg: dict):
    logger_factory = log.get("factory")
    logger = logger_factory.get_logger(module="server")
    logger.lifecycle("[SERVER] Deep enforcement checks triggered")
    daemons_cfg = cfg.get("services", {}).get("daemons", {})
    for name, daemon_cfg in daemons_cfg.items():
        if not daemon_cfg.get("check", False):
            logger.info(f"[STATUS] Skipping {name} (check=false)")
            continue
        # Pick the right subclass based on daemon type
        server_logger = logger_factory.get_logger(module=name)
        server = Server(name, daemon_cfg, server_logger)

        # Deep check includes status first
        server.check_status()
        #server.run_enforcement()  # child classes override this
# Firewall Orchestrator
def run_orchestrator(lgr_cfg: dict, cfg: dict):
    triggered = set(Flags.active_in_group("firewall", lgr_cfg["active_flags"]))
    if triggered:
        logger_factory = lgr_cfg.get("factory")
        logger = logger_factory.get_logger(module="firewall")
        logger.lifecycle(
            f"[FIREWALL] Service instantiation triggered by flags: {', '.join(triggered)}"
        )
        orch = FirewallOrchestrator(cfg, lgr_cfg)
        orch.run()

def main(argv=None):
    cfg = load_config()
    cfg = get_arguments(cfg)
    lgr_cfg = initialize_logger(cfg)
    flags = lgr_cfg.get("flags")
    if flags.get("SERVER_DEEP", False):
        run_server_deep(lgr_cfg, cfg)
    elif flags.get("SERVER_STATUS", False):
        run_server_status(lgr_cfg, cfg)
    run_orchestrator(lgr_cfg, cfg)

 
if __name__ == "__main__":
    main()