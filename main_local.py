"""
 Package: WebScanner
 Author: Leon McClatchey
 Date: 2025-11-22
 
 1) Setup the server status check and possible restart
 2) Firewall -> get status and configuration
 3) Scan Logs and modify/add rules
 
"""
# --- System Library Imports ---
import sys
import os
import time
import platform
import distro
# --- Third-party imports ---
# --- Local Project imports ---
from BotScanner.config.constants import FLAGS, BOT_PATTERNS
from BotScanner.config.inventory import InventoryLoader
from BotScanner.config.vault import VaultLoader
from BotScanner.firewall.manager import FirewallOrchestrator
#from BotScanner.firewall.weblog_parser import parse_weblog_file
from BotScanner.net.net_tools import sudo_run, update_service
from BotScanner.net.monitor_server import monitor_server
from BotScanner.utils.flags import BitmapFlags
from BotScanner.utils.inventory_resolver import resolve_server_config
from BotScanner.utils.logger import WriteLog, Logger
from BotScanner.utils.parser import ScriptParser
# Function to get the Ansible Inventory
def get_inventory(path: str, log: str | None) -> dict:
    fPath = os.path.join(path,"hosts.yml") if not path.endswith("hosts.yml") else path
    inventory = InventoryLoader(path = fPath, flags=FLAGS, log=log)
    data = inventory.load()
    log.info(f"[INVENTORY] loaded {len(data)} base objects")
    return data
# Function to read the Ansible Vault and obtain the secrets
def get_secrets(path: str, log: str | None, passwd: str):
    fPath = os.path.join(path,"vault.yml") if not path.endswith("vault.yml") else path
    vault = VaultLoader(log=log, flags=FLAGS, vault_pass=passwd, path=fPath)
    data = vault.load()
    log.info(f"[VAULT] loaded {len(data)} secret information objects")
    return data
def main():
    # Unified Project log file
    project_log_file = "~/logs/BotScanner.log"
    flags = BitmapFlags(FLAGS)
    log = Logger(name="BotScanner",flags=flags).get()
    parser = ScriptParser(flags=flags)
    args = parser.parse()
    # Convert Namespace → dict
    args_dict = vars(args)
    # Build key=value string
    log_entry = ", ".join(f"{k}={v}" for k, v in args_dict.items())
    log.info("[STARTUP] Parsed args: %s", log_entry)
    # ✅ If ANSIBLE_CFG is active, require inventory + vault password
    if flags and (flags & BitmapFlags.ANSIBLE_CFG):
        # ✅ Resolve inventory path only if ANSIBLE_CFG is active
        inventory_path = parser.resolve_inventory_path(args.inventory)
        if args.inventory and args.inventory.strip():
            log.info(f"Using provided inventory: {inventory_path}")
        else:
            log.info(f"No inventory provided, falling back to default: {inventory_path}")
        log.info(f"[INVENTORY] Using inventory: {inventory_path}")
        inventory = get_inventory(path = inventory_path, log = log)
        # ✅ Vault password resolution
        vault_password, vault_source = parser.resolve_vault_password(args.vault_pass)
        if vault_source == "file":
            log.info(f"[VAULT] Vault password loaded from file: {args.vault_pass}")
        elif vault_source == "literal":
            log.info("[VAULT] Vault password provided directly as a string")
        else:
            log.info("[VAULT] No vault password provided, vault disabled")
        secrets = get_secrets(path = inventory_path, log = log, passwd = vault_password)
    else:
        vault = None
        inventory = None
    if flags and (flags & BitmapFlags.MONITOR_SERVER):
        ctr = 0
        rc = False
        while not rc:
            rc = monitor_server({
                "host": args.host,
                "server": args.server,
                "sudo_pass": secrets.get("sudo_pass"),
                "log": log
            },inventory)
            if ctr >= 4:
                break
            else:
                ctr += 1
            key = args.server.get("server") or args.server.get("key")
            msg = f"{key} {'server' if key.lower() == 'web' else ''} {'failed' if not rc else 'started'} after {ctr} tries on {args.host}"
            log.warn(msg) if not rc else log.info(msg)
    nft_orch = FirewallOrchestrator(secrets.get("sudo_pass"),"nftables",log, flags)
    nft_orch.orchestrate()
    fwd_orch = FirewallOrchestrator(secrets.get("sudo_pass"),"firewalld",log, flags)
    fwd_orch.orchestrate()
    mask = BitmapFlags.FIREWALL_STATUS | BitmapFlags.FIREWALL_DRIFT
    if flags & mask:
        FirewallOrchestrator.run_all_backends(secrets.get("sudo_pass"), flags, log)
    sys.exit(0)

    sys.exit(0)
    # ✅ Startup banner
    WriteLog("=== BotScanner starting ===", log=log, flags=flags)
    WriteLog(f"Target host: {args.host}", log=log, flags=flags)
    # ✅ Show active flags
    active_flags = flags.summary()["active_flags"]
    WriteLog(f"Active flags: {','.join(active_flags)}", log=log, flags=flags)

    # ✅ Show detection patterns
    if flags["enable_firewall_scan"]:
        WriteLog(f"Loaded {len(BOT_PATTERNS)} bad patterns", log=log, flags=flags)
        for pat in BOT_PATTERNS:
            WriteLog(f"Pattern: {pat}", log=log, flags=flags)

    # If CLI provided --log, use that as file path override
    log_file = args.log if args.log else None
    log = Logger(log_file=log_file).get()

    WriteLog(f"Launching WebScanner for host: {args.host}", log=log)
    WriteLog(f"Flags: {flags.summary()}", log=log)


    # Run firewall sync
    if flags["ipset_mode"]:
        fw = Firewalls(log=log, flags=flags, secrets=secrets, inventory=targets)
        fw.sync(ipset=args.ipset, ipfilter=args.ipfilter)

    # Summary
    WriteLog("[SUMMARY] WebScanner completed", log=log)
    WriteLog(f"Target host: {args.host}", log=log)
    WriteLog(f"Dry-run: {flags['dry_run']}, Verbose: {flags['verbose']}", log=log)
# Function to Monitor the Server
def update_apache(service: str, password: str, log: str | None) -> bool:
    log.info(f"[SERVER] Checking Status of {service}")
    out, code, error = sudo_run(f"systemctl is-active {service}", password)
    log.info(f"[SERVER] {service} returned {out} {'Running' if code==0 else 'Crashed'}!")
    if code == 0:
        log.info(f"[SERVER] {service} is running")
        return True
    # stop service
    out, code, error = sudo_run(f"systemctl stop {service}", password)
    time.sleep(3)
    # kill leftover apache processes
    sudo_run("pkill -9 -f httpd-prefork", password)
    time.sleep(2)
    # reset the systemd state
    sudo_run(f"systemctl reset-failed {service}", password)
    # Restart the service
    out,code,err = sudo_run(f"systemctl start {service}", password)
    log.info(f"[SERVER] {service} restart {'Running' if code==0 else 'Stopped'}")
    # Final Check
    out,code,err = sudo_run(f"systemctl is-active {service}",password)
    return code == 0
if __name__ == "__main__":
    main()
