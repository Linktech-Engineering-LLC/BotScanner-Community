"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-02
Modified: 2026-02-17
File: BotScanner/firewall/backend/nftables.py
Description: nftables backend implementation for BotScanner.
"""

# System Libraries
import json
import re
import ipaddress
from pathlib import Path
# Project Libraries
from BotScanner.net import sudo_run
from BotScanner.net.discovery import NetDiscovery
from ..rule import Rule
from .backend import FirewallBackend
from .mixin import NftablesMixin

class NftablesBackend(NftablesMixin, FirewallBackend):

    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        self.sudo_password = cfg.get("secrets", {}).get("sudo_pass")
        self.name = "nftables"
        self.family = "nftables"

        # Logger factory is passed in via lgr_cfg
        self.logger_factory = lgr_cfg.get("factory")
        self.logger = self.logger_factory.get_logger("nftables")

        # Extract backend-specific config from YAML
        fw_cfg = cfg.get("firewall", {})
        backends_cfg = fw_cfg.get("backends", {})
        self.backend_cfg = backends_cfg.get(self.name, {})
        self.command = self.backend_cfg.get("command", "nft")
        self._pending_cmds = []

        if not self.backend_cfg:
            raise ValueError(f"Missing {self.name} backend configuration")

    # ----------------------------------------------------------------------
    # Capture raw nftables output
    # ----------------------------------------------------------------------
    def load_rules(self) -> dict:
        """
        Run all nftables capture commands defined in YAML.
        Returns:
            {
                "raw": {label: stdout},
                "rc": {label: return_code},
                "stderr": {label: stderr},
            }
        """
        command = self.backend_cfg.get("command", "nft")
        capture_list = self.backend_cfg.get("capture", ["list ruleset"])

        raw = {}
        rc = {}
        stderr = {}

        for entry in capture_list:
            if isinstance(entry, str):
                label = entry.strip().replace("-", "_").replace(" ", "_")
                cmd = f"{command} {entry}"
            elif isinstance(entry, dict):
                label = entry["label"]
                cmd = f"{command} {entry['cmd']}"
            else:
                raise ValueError(f"Invalid capture entry: {entry}")

            self.logger.debug(f"[NFTABLES] Running: {cmd}")

            result = sudo_run(cmd, self.sudo_password)

            raw[label] = result.msg
            rc[label] = result.code
            stderr[label] = result.err
        return {"raw": raw, "rc": rc, "stderr": stderr}

    # ----------------------------------------------------------------------
    # Normalize nftables output into backend-agnostic structure
    # ----------------------------------------------------------------------
    def normalize(self, raw: dict) -> dict:
        """
        Minimal v3 normalization for nftables.
        Extract raw ruleset text and parse it into a Python dict.
        """

        ruleset_raw = None

        inner = raw.get("raw")
        if isinstance(inner, str):
            ruleset_raw = inner
        elif isinstance(inner, dict):
            ruleset_raw = inner.get("ruleset") or inner.get("list_ruleset")
        elif "ruleset" in raw:
            ruleset_raw = raw["ruleset"]
        elif "list_ruleset" in raw:
            ruleset_raw = raw["list_ruleset"]

        parsed = None
        if isinstance(ruleset_raw, str) and ruleset_raw.strip():
            try:
                parsed = json.loads(ruleset_raw)
            except Exception as exc:
                self.logger.error(f"[NFTABLES] Failed to parse JSON: {exc}")

        return {
            "ruleset": parsed,
            "raw": ruleset_raw,
            "rc": raw.get("rc"),
            "stderr": raw.get("stderr"),
        }
        
    def save_nft(self, path: str) -> None:
        """
        Placeholder for strict enforcement mode.
        Will write the current nftables ruleset to a file.
        """
        raise NotImplementedError("save_nft() will be implemented in strict mode")

    def load_nft(self, path: str) -> None:
        """
        Placeholder for strict enforcement mode.
        Will load an nftables ruleset from a file.
        """
        raise NotImplementedError("load_nft() will be implemented in strict mode")

    # ------------------------------------------------------------
    # Table Definitions for Enforcement
    # ------------------------------------------------------------

    def create_table(self, table_name: str, table_meta: dict) -> bool:
        """
        Create an nftables table.
        table_name: "filter", "botblock", etc.
        table_meta: {"family": "inet"} or similar.
        """
        family = table_meta.get("family", "inet")
        cmd = f"{self.command} add table {family} {table_name}"
        result = sudo_run(cmd, self.sudo_password)

        # normalize if runner returns a list
        if isinstance(result, list):
            result = result[0] if result else None

        if not result or result.code != 0:
            self.logger.error(f"[NFT] Failed to create table {family} {table_name}: {result.err if result else 'no result'}")
            return False

        return True

    def get_table_family(self, table_name: str) -> str | None:
        tables = self.list_tables()  # now a list of "family name" strings

        for entry in tables:
            parts = entry.split()
            if len(parts) == 2:
                family, name = parts
                if name.lower() == table_name.lower():
                    return family.lower()

        return None
    
    def list_tables(self):
        cmd = f"{self.command} list tables"
        ns_list = sudo_run(cmd, self.sudo_password)

        # v3 runner returns a list → normalize
        if isinstance(ns_list, list):
            if not ns_list:
                return []
            ns = ns_list[0]
        else:
            ns = ns_list
    
        if ns.code != 0:
            self.logger.error(f"[NFT] Failed to list tables: {ns.err}")
            return []

        tables = []
        for line in ns.msg.splitlines():
            # nft output: "table inet filter"
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0] == "table":
                family = parts[1]
                name = parts[2]
                tables.append(f"{family} {name}")

        return tables

    def table_exists(self, table_name: str) -> bool:
        """
        Return True if the nftables table exists.
        """
        if not table_name:
            if self.logger:
                self.logger.error("[CHECK] No table name provided to table_exists()")
            return False

        # Reuse existing backend logic
        family = self.get_table_family(table_name)
        return family is not None

    def build_table_cmd(self, table_name: str) -> str:
        return f"{self.command} add table inet {table_name}"
    
    def flush_table(self, table_name: str):
        cmd = f"{self.command} flush table inet {table_name}"
        return sudo_run(cmd, self.sudo_password)

    def delete_table(self, table_name: str):
        cmd = f"{self.command} delete table inet {table_name}"
        result = sudo_run(cmd, self.sudo_password)
        return self.normalize_status(table_name, result, cmd)

    def build_table_cmd(self, table_name: str) -> str:
        return f"{self.command} add table inet {table_name}"
   
    def normalize_status(self, resource: str, result, cmd=None) -> dict:
        if result is True:
            return {
                "resource": resource,
                "code": 0,
                "status": "SUCCESS",
                "err": "",
                "cmd": cmd,
            }

        if result is None:
            return {
                "resource": resource,
                "code": -1,
                "status": "FAILURE",
                "err": "Backend returned no result",
                "cmd": cmd,
            }

        # SimpleNamespace from sudo_run
        code = getattr(result, "code", -1)
        err  = getattr(result, "err", "") or getattr(result, "stderr", "")
        out  = getattr(result, "stdout", "") or getattr(result, "msg", "")

        return {
            "resource": resource,
            "code": code,
            "status": "SUCCESS" if code == 0 else "FAILURE",
            "err": err,
            "out": out,
            "cmd": cmd,
        }
    
    # ------------------------------------------------------------
    # Table Definitions for Enforcement
    # ------------------------------------------------------------

    def add_set_element(self, table_name: str, set_name: str, addr: str, timeout: str | None):
        """
        Add a single element to an nftables set.
        Returns a normalized status dict.
        """
        if timeout:
            cmd = f"{self.command} add element inet {table_name} {set_name} {{ {addr} timeout {timeout} }}"
        else:
            cmd = f"{self.command} add element inet {table_name} {set_name} {{ {addr} }}"

        if self.logger:
            self.logger.lifecycle("DEBUG", f"[NFT] {cmd}")

        result = sudo_run(cmd, self.sudo_password)

        return self.normalize_status(set_name, result, cmd)

    def build_set_cmd(self, table_name: str, set_name: str, set_type: str, flags: list[str]) -> list[str]:
        """
        Build the nftables command to create a set.
        Backend-only: enforcer passes explicit parameters.
        """
        flags_str = ",".join(flags) if flags else ""

        # escaped braces for f-string correctness
        block = (
            f"{{ type {set_type}; flags {flags_str}; }}"
            if flags
            else f"{{ type {set_type}; }}"
        )

        return [
            self.command, "add", "set", "inet",
            table_name, set_name,
            block
        ]
    
    def build_delete_set_cmd(self, table_name: str, set_name: str) -> str:
        return f"{self.command} delete set inet {table_name} {set_name}"
        
    def delete_set(self, table_name: str, set_name: str):
        cmd = self.build_delete_set_cmd(table_name, set_name)
        result = sudo_run(cmd, self.sudo_password)
        return self.normalize_status(set_name, result, cmd)

    def get_set_elements(self, table_name: str, set_name: str) -> list[dict]:
        """
        Return a list of element dicts from an nftables set.
        Supports multi-line element blocks.
        Each element is {"addr": "...", "timeout": "..."}.
        """
        cmd = f"{self.command} list set inet {table_name} {set_name}"
        result = sudo_run(cmd, self.sudo_password)

        if result.code != 0:
            return []

        elements = []
        collecting = False
        buffer = []

        for raw_line in result.msg.splitlines():
            line = raw_line.strip()

            # Detect start of elements block
            if not collecting and "elements" in line and "{" in line:
                collecting = True

                # Capture anything after the first "{"
                after = line.split("{", 1)[1].strip()
                if after.endswith("}"):
                    # Single-line block
                    buffer.append(after[:-1])
                    collecting = False
                else:
                    buffer.append(after)
                continue

            # If we're inside a multi-line block
            if collecting:
                if "}" in line:
                    # Capture anything before "}"
                    before = line.split("}", 1)[0].strip()
                    if before:
                        buffer.append(before)
                    collecting = False
                else:
                    buffer.append(line)
                continue

        # Now parse the accumulated buffer
        # Join all lines, split by commas
        joined = " ".join(buffer)
        raw_items = [item.strip() for item in joined.split(",") if item.strip()]

        for item in raw_items:
            addr = None
            timeout = None

            tokens = item.split()

            # Find the IP address
            for tok in tokens:
                cleaned = tok.strip(",{}=")
                try:
                    ipaddress.ip_address(cleaned)
                    addr = cleaned
                    break
                except ValueError:
                    continue

            if not addr:
                continue

            # Find timeout if present
            if "timeout" in tokens:
                idx = tokens.index("timeout")
                if idx + 1 < len(tokens):
                    timeout = tokens[idx + 1]

            elements.append({"addr": addr, "timeout": timeout})

        return elements
    
    # Alias for backward compatibility
    list_set_elements = get_set_elements

    def list_sets(self, table_name: str) -> dict:
        """
        Return a dict of sets with metadata:
        {
            "botblock": {
                "type": "ipv4_addr",
                "flags": ["interval"],
                "timeout": "1h",
                "gc-interval": "30s"
            }
        }
        """
        nft_json = self._get_nft_json()
        if not nft_json:
            return {}

        sets = {}

        for item in nft_json.get("nftables", []):
            if "set" in item:
                s = item["set"]
                if s.get("table") != table_name:
                    continue

                name = s["name"]
                sets[name] = {
                    "type": s.get("type"),
                    "flags": s.get("flags", []),
                    "timeout": s.get("timeout"),
                    "gc-interval": s.get("gc-interval"),
                }

        return sets

    def add_set_elements(self, table_name: str, set_name: str, elements: list):
        if not elements:
            return True

        parts = []
        for e in elements:
            addr = e["addr"]
            timeout = e.get("timeout")
            if timeout:
                parts.append(f"{addr} timeout {timeout}")
            else:
                parts.append(addr)

        expr = "{ " + ", ".join(parts) + " }"

        cmd = [
            "nft", "-j",
            "add", "element",
            "inet", table_name, set_name,
            expr
        ]

        return self.normalize_status(set_name, self._run_nft_cmd(cmd), cmd)

    def del_set_elements(self, table_name: str, set_name: str, elements: list):
        if not elements:
            return True

        elem_list = [{"elem": e} for e in elements]

        cmd = [
            "nft", "-j", "delete", "element",
            f"inet {table_name} {set_name}",
            json.dumps(elem_list)
        ]

        return self.normalize_status(set_name, self._run_nft_cmd(cmd), cmd)

    def get_set_definition(self, table_name: str, set_name: str) -> dict:
        """
        Return a normalized set definition:
        {
            "flags": [...],
            "timeout": <str or None>,
            "elements": [{"addr": "...", "timeout": "..."}]
        }
        """
        cmd = f"{self.command} list set inet {table_name} {set_name}"
        result = sudo_run(cmd, self.sudo_password)

        # If the set doesn't exist, return empty definition
        if result.code != 0:
            return {"flags": [], "timeout": None, "elements": []}

        output = result.msg

        # Extract flags
        flags_match = re.search(r"flags\s+([^\n]+)", output)
        flags = []
        if flags_match:
            flags = flags_match.group(1).replace(",", " ").split()

        # Extract timeout (global set timeout)
        timeout_match = re.search(r"timeout\s+(\S+)", output)
        timeout = timeout_match.group(1) if timeout_match else None

        # Extract elements
        elements = self.list_set_elements(table_name, set_name)

        return {
            "flags": flags,
            "timeout": timeout,
            "elements": elements,
        }

    def set_exists(self, table_name: str, set_name: str) -> bool:
        """
        Return True if the nftables set exists.
        """
        cmd = f"{self.command} list set inet {table_name} {set_name}"
        result = sudo_run(cmd, self.sudo_password)
        return result.code == 0
    
    def create_set(self, table_name: str, pset: dict):
        set_name = pset["name"]
        set_type = pset["type"]
        flags = pset.get("flags", [])

        cmd = self.build_set_cmd(
            table_name=table_name,
            set_name=set_name,
            set_type=set_type,
            flags=flags,
        )

        result = sudo_run(cmd, self.sudo_password)
        return self.normalize_status(set_name, result, cmd)

    # ------------------------------------------------------------
    # Chain Definitions for Enforcement
    # ------------------------------------------------------------

    def create_chain(self, table_name: str, chain_name: str, meta: dict):
        cmd = self.build_chain_cmd(table_name, chain_name, meta)
        return self.normalize_status(chain_name, self._run_nft_cmd(cmd), cmd)
    def delete_chain(self, table_name: str, chain_name: str):
        cmd = self.build_delete_chain_cmd(table_name, chain_name)
        return self.normalize_status(chain_name, self._run_nft_cmd(cmd), cmd)
    def flush_chain(self, table_name: str, chain_name: str):
        cmd = self.build_flush_chain_cmd(table_name, chain_name)
        return self.normalize_status(chain_name, self._run_nft_cmd(cmd), cmd)

    def build_chain_cmd(self, table_name: str, chain_name: str, chain_cfg: dict) -> str:
        """
        Build the nft command to create a chain.

        chain_cfg keys:
        - name
        - type
        - hook
        - priority
        """
        chain_type = chain_cfg.get("type", "filter")
        hook       = chain_cfg.get("hook", "input")
        priority   = chain_cfg.get("priority", 0)

        return (
            f"{self.command} add chain inet {table_name} {chain_name} "
            f"{{ type {chain_type} hook {hook} priority {priority}; }}"
        )
    
    def build_list_chain_cmd(self, table_name: str, chain_name: str) -> str:
        return f"{self.command} list chain inet {table_name} {chain_name}"

    def build_delete_chain_cmd(self, table_name: str, chain_name: str) -> str:
        return f"{self.command} delete chain inet {table_name} {chain_name}"

    def build_flush_chain_cmd(self, table_name: str, chain_name: str) -> str:
        return f"{self.command} flush chain inet {table_name} {chain_name}"

    def extract_chains(self, table_name: str) -> dict:
        """
        Extract and normalize chain information from nftables.

        Returns:
            {
                "chain_name": {
                    "type": "filter",
                    "hook": "input",
                    "priority": 0
                },
                ...
            }
        """

        results = {}

        cmd = f"{self.command} -j list table inet {table_name}"
        ns = sudo_run(cmd, self.sudo_password)

        if ns.code != 0:
            if self.logger:
                self.logger.warning(f"[NFT] Failed to list table {table_name}")

        try:
            data = json.loads(ns.msg)
        except Exception as e:
            if self.logger:
                self.logger.error(f"[NFT] JSON parse error for table {table_name}: {e}")

        # nftables JSON structure:
        # { "nftables": [ { "table": {...} }, { "chain": {...} }, ... ] }
        for entry in data.get("nftables", []):
            if "chain" not in entry:
                continue

            chain = entry["chain"]

            name = chain.get("name")
            if not name:
                continue

            # Normalize fields
            chain_type = chain.get("type")
            hook       = chain.get("hook")
            priority   = chain.get("prio") or chain.get("priority")

            results[name] = {
                "type": chain_type,
                "hook": hook,
                "priority": priority,
            }

        return results

    # ----------------------------------------------------------------------
    # v3 ENFORCEMENT API
    # ----------------------------------------------------------------------

    def apply_rule(self, rule):
        """
        v3: Apply a Rule object by building the nft command and queuing it.
        """
        cmd = self.build_rule_cmd_from_rule(rule)
        self._pending_cmds.append(cmd)


    def delete_rule(self, rule):
        """
        v3: Delete a Rule object by building the delete command.
        """
        # You already have build_rule_cmd; now add a delete wrapper
        expr = self.build_expr(rule)
        cmd = (
            f"{self.command} delete rule inet {rule.table} {rule.chain} "
            f"{expr}"
        )
        self._pending_cmds.append(cmd)


    def commit(self):
        """
        Execute all queued nft commands atomically.
        """
        for cmd in self._pending_cmds:
            result = sudo_run(cmd, self.sudo_password)
            if result.code != 0:
                if self.logger:
                    self.logger.error(f"[NFT] Command failed: {cmd}\n{result.err}")
                raise RuntimeError(f"nft command failed: {cmd}")

        self._pending_cmds.clear()


    # ----------------------------------------------------------------------
    # v3 ENTRY POINT
    # ----------------------------------------------------------------------

    def build_rule_cmd_from_rule(self, rule):
        """
        v3: Accept a Rule object and build a full nft command.
        """
        expr = self.build_expr(rule)
        return self.build_rule_cmd(rule.table, rule.chain,
                                   {"expr": expr, "comment": rule.comment})

    # ----------------------------------------------------------------------
    # v2-compatible wrapper (kept for orchestrator compatibility)
    # ----------------------------------------------------------------------

    def build_rule_cmd(self, table_name: str, chain_name: str, rule_cfg: dict) -> str:
        """
        Build an nft command to add a rule to a chain.

        rule_cfg keys:
        - expr (raw nft expression string)
        - comment (optional)
        """
        expr = rule_cfg.get("expr")
        comment = rule_cfg.get("comment")

        if comment:
            return (
                f"{self.command} add rule inet {table_name} {chain_name} "
                f"{expr} comment \"{comment}\""
            )

        return (
            f"{self.command} add rule inet {table_name} {chain_name} "
            f"{expr}"
        )

    # ----------------------------------------------------------------------
    # v3 EXPRESSION BUILDER
    # ----------------------------------------------------------------------

    def build_expr(self, rule):
        """
        Build deterministic nftables expression from a flat Rule object.
        """
        if rule.raw:
            return rule.raw

        parts = []

        # protocol
        if rule.protocol:
            parts.append(f"meta l4proto {rule.protocol}")

        # src/dst
        if rule.src:
            parts.append(f"ip saddr {rule.src}")
        if rule.dst:
            parts.append(f"ip daddr {rule.dst}")

        # ports (assume tcp for now; you can extend)
        if rule.sport is not None:
            parts.append(f"tcp sport {rule.sport}")
        if rule.dport is not None:
            parts.append(f"tcp dport {rule.dport}")

        # interface
        if rule.interface:
            parts.append(f"iifname {rule.interface}")

        # action
        parts.append(rule.action)

        # counter
        if rule.counter:
            parts.append("counter")

        return " ".join(parts)

    # ----------------------------------------------------------------------
    # FIELD EMITTER
    # ----------------------------------------------------------------------

    def emit_field(self, field_obj):
        """
        Emit a single match field.

        Handles:
        - literal
        - list
        - range
        - set reference
        """
        prefix = self._field_prefix(field_obj)

        # Set reference
        if getattr(field_obj, "is_set", False) and field_obj.ref_name:
            return f"{prefix} @{field_obj.ref_name}"

        v = field_obj.value

        # Single literal
        if isinstance(v, str):
            return f"{prefix} {v}"

        # List of literals
        if isinstance(v, list):
            inner = ", ".join(v)
            return f"{prefix} {{ {inner} }}"

        # Range
        if isinstance(v, tuple) and len(v) == 2:
            return f"{prefix} {v[0]}-{v[1]}"

        # Unknown
        self.logger.warning(f"Unknown field value for nft emit: {field_obj!r}")
        return prefix

    # ----------------------------------------------------------------------
    # HELPERS
    # ----------------------------------------------------------------------

    def _field_prefix(self, field_obj):
        """
        Map Field to nftables prefix.

        Examples:
        - ip saddr
        - ip6 daddr
        - tcp sport
        - tcp dport
        """
        # src/dst
        if field_obj.key in ("saddr", "daddr"):
            return f"{field_obj.family} {field_obj.key}"

        # ports (default to tcp; you can extend later)
        if field_obj.key in ("sport", "dport"):
            return f"tcp {field_obj.key}"

        return f"{field_obj.family} {field_obj.key}"

    def status(self) -> bool:
        result = sudo_run("nft list ruleset", self.sudo_password)
        return result.code == 0

    # ------------------------------------------------------------
    # Rule Definitions Backend Loading
    # ------------------------------------------------------------

    def parse_rules(self) -> list[Rule]:
        """
        v3 nftables rule capture:
        - call _get_nft_json() to retrieve native nftables JSON
        - normalize and filter
        - convert to Rule objects
        """
        nft_json = self._get_nft_json()
        if not nft_json:
            self.logger.error("[NFTABLES] No JSON returned from _get_nft_json()")
            return []

        ruleset = nft_json.get("nftables")
        if not ruleset:
            self.logger.error("[NFTABLES] JSON missing 'nftables' key")
            return []

        rules = self._rules_from_nft(nft_json)
        return rules

    def _rules_from_nft(self, ruleset: dict) -> list[Rule]:
        """
        Convert native nftables JSON into v3 Rule objects.
        Filters out firewalld's synthetic 'inet firewalld' table.
        """

        rules: list[Rule] = []

        nft_list = ruleset.get("nftables", [])
        if not isinstance(nft_list, list):
            return rules

        current_table = None
        current_family = None
        current_chain = None

        for entry in nft_list:

            # Table entry
            if "table" in entry:
                tbl = entry["table"]
                current_table = tbl.get("name")
                current_family = tbl.get("family")
                continue

            # Chain entry
            if "chain" in entry:
                ch = entry["chain"]
                current_chain = ch.get("name")
                continue

            # Rule entry
            if "rule" in entry:
                raw_rule = entry["rule"]

                # Extract family/table/chain from rule if present
                family = raw_rule.get("family", current_family)
                table = raw_rule.get("table", current_table)
                chain = raw_rule.get("chain", current_chain)

                # ❌ Filter out firewalld synthetic table
                if family == "inet" and table == "firewalld":
                    continue

                rule = self._nft_raw_to_rule(raw_rule, table, chain, family)
                if rule:
                    rules.append(rule.with_rule_id())

        return rules
    
    def _nft_raw_to_rule(self, raw: dict, table: str, chain_name: str, family: str) -> Rule | None:
        if not isinstance(raw, dict):
            return None

        action = self._map_nft_action(raw)

        proto = None
        sport = None
        dport = None
        src = None
        dst = None
        iif = None
        oif = None
        counter = False

        exprs = raw.get("expr", [])
        if not isinstance(exprs, list):
            exprs = []

        for expr in exprs:
            if not isinstance(expr, dict):
                continue

            # match blocks
            if "match" in expr:
                m = expr["match"]
                left = m.get("left", {})
                right = m.get("right")

                if left.get("meta") == "l4proto":
                    proto = right

                if left.get("payload") == "ip saddr":
                    src = right
                if left.get("payload") == "ip daddr":
                    dst = right

                if left.get("payload") == "th dport":
                    dport = int(right)
                if left.get("payload") == "th sport":
                    sport = int(right)

            # interface meta
            if "meta" in expr:
                meta = expr["meta"]
                key = meta.get("key")
                value = meta.get("value")

                if key == "iifname":
                    iif = value
                if key == "oifname":
                    oif = value

            # counter flag
            if "counter" in expr:
                counter = True

        return Rule(
            family=family or "inet",
            table=table,
            chain=chain_name,
            protocol=proto,
            sport=sport,
            dport=dport,
            src=src,
            dst=dst,
            interface=iif or oif,
            action=action,
            comment="nftables:kernel",
            counter=counter,
        )
        
    def _map_nft_action(self, raw: dict) -> str:
        verdict = raw.get("verdict")
        if not verdict:
            return "accept"  # nft default

        vtype = verdict.get("type")
        if vtype in ("accept", "drop", "reject", "return", "continue"):
            return vtype

        if vtype == "jump":
            return "jump"

        # Unknown verdict
        self.logger.debug(f"[NFTABLES] Unknown verdict type: {vtype}")
        return vtype
    
    def _run_nft_cmd(self, cmd):
        """
        Run an nft command using sudo_run() and return the result object.
        Accepts either a list of strings or a preformatted string.
        """

        # Normalize to string
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        elif isinstance(cmd, str):
            cmd_str = cmd
        else:
            raise TypeError(f"nft command must be list[str] or str, got {type(cmd)}")

        result = sudo_run(cmd_str, self.sudo_password)

        if result.code != 0:
            self.logger.error(f"[NFTABLES] Command failed: {cmd_str} → {result.err}")

        return result

    def _build_nft_add_cmd(self, rule: Rule) -> str:
        """
        Convert a canonical Rule object into an nft 'add rule' command.
        """
        parts = [
            "nft", "add", "rule",
            rule.family,
            rule.table,
            rule.chain,
        ]

        if rule.proto:
            parts += ["meta", "l4proto", rule.proto]

        if rule.src:
            parts += ["ip", "saddr", rule.src]

        if rule.dst:
            parts += ["ip", "daddr", rule.dst]

        if rule.sport:
            parts += ["tcp", "sport", str(rule.sport)]

        if rule.dport:
            parts += ["tcp", "dport", str(rule.dport)]

        if rule.interface:
            parts += ["iifname", rule.interface]

        if rule.action:
            parts.append(rule.action)

        return " ".join(parts)

    def _build_nft_delete_cmd(self, rule: Rule) -> str:
        """
        Convert a canonical Rule object into an nft 'delete rule' command.
        """
        parts = [
            "nft", "delete", "rule",
            rule.family,
            rule.table,
            rule.chain,
        ]

        # nft delete rule requires a handle OR a full match expression.
        # Since we are canonical, we reconstruct the match expression.
        # This is the same as add, but without the action.
        if rule.proto:
            parts += ["meta", "l4proto", rule.proto]

        if rule.src:
            parts += ["ip", "saddr", rule.src]

        if rule.dst:
            parts += ["ip", "daddr", rule.dst]

        if rule.sport:
            parts += ["tcp", "sport", str(rule.sport)]

        if rule.dport:
            parts += ["tcp", "dport", str(rule.dport)]

        if rule.interface:
            parts += ["iifname", rule.interface]

        return " ".join(parts)

    def apply_canonical(self, canonical):
        self.create_table(canonical.table)

        for s in canonical.sets:
            self.create_set(s)

        for c in canonical.chains:
            self.create_chain(c)

        for r in canonical.rules:
            self.add_rule(r)
