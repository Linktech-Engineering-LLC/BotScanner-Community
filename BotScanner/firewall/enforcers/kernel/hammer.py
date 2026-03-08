# botscanner/enforcers/hammer.py
"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-14
Modified: 2026-02-17
File: BotScanner/firewall/enforcers/hammer.py
Description: Describe the purpose of this file
"""
# System Libraries
from typing import Optional
from pathlib import Path
# Project Libraries
from ..result import EnforcementResult
from ..policy import EnforcementPolicy
from ...baseline import BaseLine
from ...backend.nftables import NftablesBackend
from ...rule import Rule


class KernelHammer:
    """
    Full enforcement driver (the 'big hammer').

    Responsibilities:
    - Validate kernel state
    - Bootstrap when baseline or kernel is invalid
    - Recover from nxt if available
    - Perform full canonical enforcement (tables, sets, chains, rules)
    - Write baseline + nxt after enforcement

    This class does NOT:
    - Parse logs
    - Update botblock elements
    - Perform runtime drift correction
    - Touch activation_map or element_map
    """
    def __init__(self, cfg, lgr_cfg, backend, activation_map, element_map, canonical):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg

        # Logger factory is passed in via lgr_cfg
        self.logger_factory = lgr_cfg.get("factory")
        self.logger = self.logger_factory.get_logger("nftables")

        # backend enforcer (nftables, iptables, etc.)
        self.backend = backend
        self.backend_impl = NftablesBackend(self.cfg, self.lgr_cfg)

        # v3 truth sources
        self.activation_map = activation_map
        self.element_map = element_map
        self.canonical = canonical

    # ------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------
    def enforce(self) -> EnforcementResult:
        result = EnforcementResult()

        # ------------------------------------------------------------
        # 1. Canonical is already injected at init
        # ------------------------------------------------------------
        canonical = self.canonical
        if canonical is None:
            return result.fail("Canonical state missing in Hammer")

        # ------------------------------------------------------------
        # 2. Determine lifecycle state
        # ------------------------------------------------------------
        lifecycle = self._pre_enforcement_checks()  # BOOTSTRAP or NORMAL
        release_class = self.license.release_class  # DEV/COM/PRO/ENT

        # ------------------------------------------------------------
        # 3. Lifecycle: apply_canonical()
        # ------------------------------------------------------------
        if lifecycle == LifecycleState.BOOTSTRAP:
            if release_class == ReleaseClass.DEV:
                lc = self.backend.apply_canonical(canonical, mode="rebuild")

            elif release_class in (ReleaseClass.COM, ReleaseClass.PRO):
                lc = self.backend.apply_canonical(canonical, mode="adopt")

            elif release_class == ReleaseClass.ENT:
                lc = self.backend.apply_canonical(canonical, mode="none")

            result.merge(lc)
            if not lc.ok:
                return result

        # ------------------------------------------------------------
        # 4. Enforcement mode routing
        # ------------------------------------------------------------
        mode = self.policy.enforcement_mode

        if mode == EnforcementMode.STRICT:
            flags = dict(strict=True, audit=False, hybrid=False)

        elif mode == EnforcementMode.AUDIT_ONLY:
            flags = dict(strict=False, audit=True, hybrid=False)

        elif mode == EnforcementMode.HYBRID:
            flags = dict(strict=False, audit=False, hybrid=True)

        else:
            self.logger.error(f"Unknown enforcement mode '{mode}', falling back to strict")
            flags = dict(strict=True, audit=False, hybrid=False)

        # ------------------------------------------------------------
        # 5. Enforcement pipeline
        # ------------------------------------------------------------
        r_tables = self._enforce_tables(canonical, **flags)
        result.merge(r_tables)

        r_sets = self._enforce_sets(canonical, **flags)
        result.merge(r_sets)

        r_chains = self._enforce_chains(canonical, **flags)
        result.merge(r_chains)

        r_rules = self._enforce_rules(canonical, **flags)
        result.merge(r_rules)

        if not result.ok:
            return result

        # ------------------------------------------------------------
        # 6. Write baseline/nxt if allowed
        # ------------------------------------------------------------
        if mode != EnforcementMode.AUDIT_ONLY:
            self._write_baseline_and_nxt(canonical)

        return result
                    
    # ------------------------------------------------------------
    # Pre-enforcement checks (baseline, kernel, nxt recovery)
    # ------------------------------------------------------------
    def _pre_enforcement_checks(self) -> dict:
        """
        v3 lifecycle checks:
        - validate baseline
        - attempt nxt recovery if baseline invalid
        - fall back to bootstrap
        - return structured lifecycle status

        This method:
        - loads the raw baseline rules (if any)
        - validates that the YAML-declared table exists in both baseline and kernel
        - attempts .nxt recovery when baseline is invalid
        - does NOT parse the baseline (that happens later in enforce())
        - sets self.baseline_rules for later use
        """

        backend_impl = self.backend_impl

        nxt_path = BaseLine.baseline_path(
            cfg=self.cfg,
            owner="kernel",
            backend="nftables",
            file_type="nft",
        )

        # ------------------------------------------------------------
        # 1. Load baseline (raw rules)
        # ------------------------------------------------------------
        baseline_rules = self.backend.load_kernel_baseline()
        baseline_exists = bool(baseline_rules)

        # ------------------------------------------------------------
        # 2. Check live kernel state
        # ------------------------------------------------------------
        live_tables = backend_impl.list_tables()
        yaml_table_name = self.cfg["firewall"]["table"]["name"].lower()

        # Determine baseline validity
        if not baseline_exists:
            baseline_invalid = True
        else:
            # Extract table names from baseline (adjust to your baseline format)
            baseline_tables = {
                t["name"].lower()
                for t in baseline_rules.get("tables", [])
            }

            baseline_invalid = (
                yaml_table_name not in live_tables or
                yaml_table_name not in baseline_tables
            )

        # ------------------------------------------------------------
        # 3. Baseline invalid → attempt nxt recovery
        # ------------------------------------------------------------
        if baseline_invalid:
            if baseline_exists:
                self.logger.lifecycle(
                    f"[HAMMER] Baseline exists but kernel/baseline missing required table '{yaml_table_name}'"
                )
            else:
                self.logger.lifecycle("[HAMMER] No baseline; entering recovery/rebuild path")

            # Try nxt recovery
            if nxt_path.exists():
                self.logger.lifecycle(f"[HAMMER] Found nxt at {nxt_path}; loading into kernel")

                try:
                    backend_impl.load_nxt_into_kernel(nxt_path)

                    # Parse kernel rules after nxt load and write a fresh baseline
                    new_baseline_rules = backend_impl.parse_kernel_rules()
                    self.backend.save_kernel_baseline(new_baseline_rules)

                    self.baseline_rules = new_baseline_rules

                    return {
                        "status": "RECOVERED_FROM_NXT",
                        "baseline_written": True,
                        "nxt_used": str(nxt_path),
                    }

                except Exception as e:
                    self.logger.error(f"[HAMMER] nxt recovery failed: {e}")
                    # fall through to bootstrap

            # No valid baseline and no usable nxt → BOOTSTRAP
            self.logger.lifecycle(
                "[HAMMER] No valid baseline and no usable nxt; BOOTSTRAP required"
            )
            self.baseline_rules = None
            return {"status": "BOOTSTRAP"}

        # ------------------------------------------------------------
        # 4. Normal path (baseline valid)
        # ------------------------------------------------------------
        self.logger.lifecycle("[HAMMER] Valid baseline found; proceeding with normal enforcement")

        # Store raw baseline rules for later parsing in enforce()
        self.baseline_rules = baseline_rules

        return {"status": "NORMAL"}
        
    def _save_kernel_baseline(self, rules: list[Rule]) -> None:
        """
        Persist the canonical kernel baseline for nftables.
        """

        # 1. Make canonical rules available for freshness checks
        self.baseline_store.set_current_canonical_rules(
            owner="kernel",
            backend="nftables",
            rules=rules,
        )

        # 2. Persist baseline + checksum + TXT + metadata
        self.baseline_store.save_backend_baseline(
            owner="kernel",
            backend="nftables",
            rules=rules,
        )
        
    def _load_kernel_baseline(self) -> Optional[list[Rule]]:
        """
        Load the canonical kernel baseline for nftables.

        Returns:
            list[Rule]  → baseline exists and is valid
            None        → baseline missing or invalid
        """

        try:
            baseline = self.baseline_store.load_backend_baseline(
                owner="kernel",
                backend="nftables",
            )
        except Exception as e:
            self.logger.error(f"[BASELINE] Failed to load kernel baseline: {e}")
            return None

        # BaselineStore should return None if missing, but we guard anyway
        if not baseline:
            return None

        # Convert raw dicts → Rule objects
        try:
            rules = [Rule(**rule_dict) for rule_dict in baseline]
        except Exception as e:
            self.logger.error(f"[BASELINE] Invalid baseline format: {e}")
            return None

        return rules

    # ------------------------------------------------------------
    # Table Enforcement
    # ------------------------------------------------------------

    def check_table_family_drift(self, table_name: str) -> bool:
        """
        v3: return True if drift exists, False otherwise.
        No status dicts, no codes, no logging here.
        """

        table_cfg = self.canonical.tables.get(table_name, {})
        expected = table_cfg.get("family", "inet").lower()

        actual = self.backend_impl.get_table_family(table_name)

        if actual is None:
            # Table missing → treat as drift
            return True

        return actual.lower() != expected

    def enforce_tables(self, policy):
        """
        v3 table enforcement:
        - detect drift (missing, extra, family mismatch)
        - classify drift (critical only)
        - enforce based on policy
        - return EnforcementResult
        """

        result = EnforcementResult()
        backend = self.backend

        # ------------------------------------------------------------
        # 1. Canonical tables (from backend registry)
        # ------------------------------------------------------------
        canonical_tables = self.backend_registry.get("tables", {})

        # ------------------------------------------------------------
        # 2. Live tables (from kernel)
        # ------------------------------------------------------------
        live_tables = backend.list_tables()  # { "inet": ["botscanner"], "ip": [...], ... }

        # Normalize live tables into a flat dict: { "botscanner": "inet" }
        live_flat = {}
        for family, names in live_tables.items():
            for name in names:
                live_flat[name] = family

        # ------------------------------------------------------------
        # 3. Drift detection + classification
        # ------------------------------------------------------------
        drift = {
            "critical": [],
            "noncritical": [],
        }

        # --- Missing tables (critical) ---
        for table_name, table_def in canonical_tables.items():
            expected_family = table_def.get("family", "inet")

            if table_name not in live_flat:
                drift["critical"].append(f"missing_table: {table_name}")
                continue

            # --- Family mismatch (critical) ---
            live_family = live_flat[table_name]
            if live_family != expected_family:
                drift["critical"].append(
                    f"family_mismatch: {table_name} expected={expected_family} got={live_family}"
                )

        # --- Extra tables (critical) ---
        for live_name, live_family in live_flat.items():
            if live_name not in canonical_tables:
                drift["critical"].append(f"extra_table: {live_name}")

        # ------------------------------------------------------------
        # 4. Enforcement decisions (policy-driven)
        # ------------------------------------------------------------
        # strict → enforce_all
        # hybrid → enforce_critical only
        # audit → enforce none

        # Missing tables
        for table_name, table_def in canonical_tables.items():
            expected_family = table_def.get("family", "inet")

            if table_name not in live_flat:
                if policy.enforce_all or policy.enforce_critical:
                    ok = backend.create_table(expected_family, table_name)
                    result.add_action("create_table", table_name, ok)
                continue

            # Family mismatch
            live_family = live_flat[table_name]
            if live_family != expected_family:
                if policy.enforce_all or policy.enforce_critical:
                    backend.delete_table(live_family, table_name)
                    ok = backend.create_table(expected_family, table_name)
                    result.add_action("recreate_table", table_name, ok)

        # Extra tables
        for live_name, live_family in live_flat.items():
            if live_name not in canonical_tables:
                if policy.enforce_all or policy.enforce_critical:
                    ok = backend.delete_table(live_family, live_name)
                    result.add_action("delete_extra_table", live_name, ok)

        # ------------------------------------------------------------
        # 5. Attach drift info if classification is enabled
        # ------------------------------------------------------------
        if policy.drift_detect:
            result.details["drift"] = drift

        return result

        # ------------------------------------------------------------
        # 3. No drift
        # ------------------------------------------------------------
        self.logger.info(f"[NFT] Table {table_name} exists and matches expected family")
        result.details["drift"] = False
        return result
                    
    def recreate_table(self, table_name: str, table_meta: dict):
        """
        v3: delete + create using backend_impl.
        No command building, no sudo_run.
        """

        self.logger.lifecycle("START_RUN", f"[NFT] Recreating table {table_name}")

        # Delete (backend_impl handles "does not exist")
        self.backend_impl.delete_table(table_name)

        # Create
        self.backend_impl.create_table(table_name, table_meta)

        self.logger.lifecycle("END_RUN", f"[NFT] Table {table_name} recreated")

    # ------------------------------------------------------------
    # Set Enforcement
    # ------------------------------------------------------------
    def enforce_sets(self, policy):
        result = EnforcementResult()
        backend = self.backend

        canonical = self.backend_registry.get("sets", {})
        live = backend.list_sets()

        drift = {"critical": [], "noncritical": []}

        # -------------------------
        # Drift detection
        # -------------------------
        for name, cdef in canonical.items():
            if name not in live:
                drift["critical"].append(f"missing_set:{name}")
                continue

            ldef = live[name]

            # type mismatch
            if ldef.get("type") != cdef.get("type"):
                drift["critical"].append(
                    f"type_mismatch:{name} expected={cdef.get('type')} got={ldef.get('type')}"
                )

            # flags mismatch
            exp_flags = sorted(cdef.get("flags", []))
            live_flags = sorted(ldef.get("flags", []))
            if exp_flags != live_flags:
                drift["critical"].append(
                    f"flags_mismatch:{name} expected={exp_flags} got={live_flags}"
                )

            # ordering drift
            exp_elems = cdef.get("elements", [])
            live_elems = ldef.get("elements", [])
            if sorted(exp_elems) == sorted(live_elems) and exp_elems != live_elems:
                drift["noncritical"].append(f"ordering_drift:{name}")

        # extra sets
        for lname in live:
            if lname not in canonical:
                drift["critical"].append(f"extra_set:{lname}")

        # -------------------------
        # Enforcement
        # -------------------------
        for name, cdef in canonical.items():
            family = cdef.get("family", "inet")
            stype = cdef.get("type")
            flags = cdef.get("flags", [])
            elems = cdef.get("elements", [])

            # missing
            if name not in live:
                if policy.enforce_all or policy.enforce_critical:
                    ok = backend.create_set(family, name, stype, flags)
                    if ok and elems:
                        ok = backend.set_elements(family, name, elems)
                    result.add_action("create_set", name, ok)
                continue

            ldef = live[name]

            # type mismatch
            if ldef.get("type") != stype:
                if policy.enforce_all or policy.enforce_critical:
                    backend.delete_set(family, name)
                    ok = backend.create_set(family, name, stype, flags)
                    if ok and elems:
                        ok = backend.set_elements(family, name, elems)
                    result.add_action("recreate_set_type", name, ok)

            # flags mismatch
            exp_flags = sorted(flags)
            live_flags = sorted(ldef.get("flags", []))
            if exp_flags != live_flags:
                if policy.enforce_all or policy.enforce_critical:
                    backend.delete_set(family, name)
                    ok = backend.create_set(family, name, stype, flags)
                    if ok and elems:
                        ok = backend.set_elements(family, name, elems)
                    result.add_action("recreate_set_flags", name, ok)

            # ordering drift
            exp_elems = elems
            live_elems = ldef.get("elements", [])
            if sorted(exp_elems) == sorted(live_elems) and exp_elems != live_elems:
                if policy.enforce_all or policy.enforce_noncritical:
                    ok = backend.set_elements(family, name, exp_elems)
                    result.add_action("fix_ordering", name, ok)

        # extra sets
        for lname, ldef in live.items():
            if lname not in canonical:
                if policy.enforce_all or policy.enforce_critical:
                    family = ldef.get("family", "inet")
                    ok = backend.delete_set(family, lname)
                    result.add_action("delete_extra_set", lname, ok)

        # -------------------------
        # Attach drift
        # -------------------------
        if policy.drift_detect:
            result.details["drift"] = drift

        return result
                
    def compare_set_metadata(self, canonical_pset, kernel_pset):
        """
        Compare canonical set metadata with kernel set metadata.
        Returns a dict of differences, or {} if identical.
        """
        diffs = {}

        # type
        if canonical_pset.get("type") != kernel_pset.get("type"):
            diffs["type"] = {
                "kernel": kernel_pset.get("type"),
                "canonical": canonical_pset.get("type"),
            }

        # flags
        if set(canonical_pset.get("flags", [])) != set(kernel_pset.get("flags", [])):
            diffs["flags"] = {
                "kernel": kernel_pset.get("flags", []),
                "canonical": canonical_pset.get("flags", []),
            }

        # timeout
        if canonical_pset.get("timeout") != kernel_pset.get("timeout"):
            diffs["timeout"] = {
                "kernel": kernel_pset.get("timeout"),
                "canonical": canonical_pset.get("timeout"),
            }

        # gc-interval
        if canonical_pset.get("gc-interval") != kernel_pset.get("gc-interval"):
            diffs["gc-interval"] = {
                "kernel": kernel_pset.get("gc-interval"),
                "canonical": canonical_pset.get("gc-interval"),
            }

        return diffs
        
    def resolve_elements(self, set_name: str, activation: dict) -> list[dict]:
        """
        v3 element resolution:
        - activation_map drives required/active
        - merge rule-driven, YAML-driven, and activation-driven elements
        - dedupe by canonical element key (addr)
        - return a normalized list of element dicts
        """

        required = activation.get("required", False)
        active = activation.get("active", False)

        final: list[dict] = []

        # ------------------------------------------------------------
        # 2. Static YAML elements (from SetElementBuilder)
        # ------------------------------------------------------------
        if required or active:
            yaml_elems = self.element_map.get(set_name, [])
            # element_map entries are already normalized
            final.extend(yaml_elems)

        # ------------------------------------------------------------
        # 3. Activation-derived elements (runtime additions)
        # ------------------------------------------------------------
        if active:
            # activation["elements"] is authoritative for runtime additions
            final.extend(activation.get("elements", []))

        # ------------------------------------------------------------
        # 4. Deduplicate by canonical key (addr)
        # ------------------------------------------------------------
        seen = set()
        deduped = []

        for elem in final:
            key = elem.get("addr")
            if not key:
                continue
            if key not in seen:
                seen.add(key)
                deduped.append(elem)

        # ------------------------------------------------------------
        # 5. Logging
        # ------------------------------------------------------------
        self.logger.lifecycle(
            "RESOLVE",
            f"[NFT] Set {set_name} resolved {len(deduped)} elements "
            f"(required={required}, active={active})"
        )

        return deduped

    def resolve_rule_elements(self, set_cfg):
        """
        Extract rule-driven elements for this set.
        v3: iterate rules from backend_registry, not self.all_rules.
        """

        target = set_cfg["name"]
        elements = []

        # Iterate rules by table
        for table_name, table in self.backend_registry.items():
            for rule in table["rules"]:

                # Only these fields can reference sets
                fields = [rule.src, rule.dst, rule.sport, rule.dport]

                for field in fields:
                    if not field:
                        continue

                    # Must be a set reference AND must match this set
                    if getattr(field, "is_set", False) and field.ref_name == target:
                        # Convert the field's value(s) into nftables element dicts
                        elems = self._field_to_elements(field)
                        elements.extend(elems)

        return elements

    def rule_to_element(self, rule: Rule) -> dict | None:
        """
        Convert a canonical Rule into an nftables set element dict.
        Only fields that logically map to set elements are included.
        """

        # Address-based elements
        if rule.src:
            return {"addr": rule.src}

        if rule.dst:
            return {"addr": rule.dst}

        # Port-based elements
        if rule.sport is not None:
            return {"port": rule.sport}

        if rule.dport is not None:
            return {"port": rule.dport}

        # No element produced
        return None

    def should_create_set(set_cfg, activation):
        return set_cfg.get("required") or activation["active"]

    def sync_set_elements(self, table_name, set_name, desired):
        """
        Returns:
            (changed_count, error)
            changed_count: number of elements added or removed
            error: backend error dict, or None on success
        """
        actual = self.backend.get_set_elements(table_name, set_name)

        actual_addrs = {e["addr"] for e in actual}
        desired_addrs = {e["addr"] for e in desired}

        missing = desired_addrs - actual_addrs
        extra   = actual_addrs - desired_addrs

        changed = 0

        # ADD missing elements
        if missing:
            to_add = [e for e in desired if e["addr"] in missing]
            res = self.backend.add_set_elements(table_name, set_name, to_add)
            if res.get("status") != "SUCCESS":
                return changed, res
            changed += len(to_add)

        # DELETE extra elements
        if extra:
            to_del = [e for e in actual if e["addr"] in extra]
            res = self.backend.del_set_elements(table_name, set_name, to_del)
            if res.get("status") != "SUCCESS":
                return changed, res
            changed += len(to_del)

        return changed, None

    # ------------------------------------------------------------
    # Chain Enforcement
    # ------------------------------------------------------------

    def enforce_chains(self, mode="strict"):
        """
        v3 chain enforcement with mode support:
        - strict  → enforce fully
        - audit   → detect drift only, no kernel writes
        - hybrid  → enforce critical drift, ignore cosmetic drift
        """

        result = EnforcementResult()

        # v3 supports exactly one table
        table_name, table = next(iter(self.backend_registry.items()))
        activation_chains = self.activation_map.get("chains", {})

        # kernel truth: dict of chain_name → metadata
        kernel_chains = self.backend_impl.extract_chains(table_name)

        # ------------------------------------------------------------
        # 1. Create missing required chains
        # ------------------------------------------------------------
        for cname, meta in activation_chains.items():
            if meta.get("required") and cname not in kernel_chains:

                # Missing chain = critical drift
                if mode == "audit":
                    result.details.setdefault("missing_chains", []).append(cname)
                    result.status = "DRIFT"
                    continue

                # strict or hybrid → create
                r = self._safe_backend_call(
                    "create_chain",
                    self.backend_impl.create_chain,
                    table_name,
                    cname,
                    meta
                )
                if r.ok:
                    result.bump("created")
                else:
                    result.add_error(r.errors[0])

        # refresh kernel truth
        kernel_chains = self.backend_impl.extract_chains(table_name)

        # ------------------------------------------------------------
        # 2. Delete extra chains (present in backend but not activation)
        # ------------------------------------------------------------
        for cname in list(kernel_chains):
            if cname not in activation_chains:

                # Extra chain = critical drift
                if mode == "audit":
                    result.details.setdefault("extra_chains", []).append(cname)
                    result.status = "DRIFT"
                    continue

                # strict or hybrid → delete
                r = self._safe_backend_call(
                    "delete_chain",
                    self.backend_impl.delete_chain,
                    table_name,
                    cname
                )
                if r.ok:
                    result.bump("deleted")
                else:
                    result.add_error(r.errors[0])

        # refresh kernel truth
        kernel_chains = self.backend_impl.extract_chains(table_name)

        # ------------------------------------------------------------
        # 3. Drift detection + recreation
        # ------------------------------------------------------------
        for cname, meta in activation_chains.items():
            if cname in kernel_chains:

                drift = self.chain_drift(meta, kernel_chains[cname])

                if drift:
                    # Drifted chain = critical drift
                    if mode == "audit":
                        result.details.setdefault("chain_drift", []).append(cname)
                        result.status = "DRIFT"
                        continue

                    # strict or hybrid → recreate
                    r1 = self._safe_backend_call(
                        "delete_chain",
                        self.backend_impl.delete_chain,
                        table_name,
                        cname
                    )
                    r2 = self._safe_backend_call(
                        "create_chain",
                        self.backend_impl.create_chain,
                        table_name,
                        cname,
                        meta
                    )

                    if r1.ok and r2.ok:
                        result.bump("changed")
                    else:
                        if not r1.ok:
                            result.add_error(r1.errors[0])
                        if not r2.ok:
                            result.add_error(r2.errors[0])

        # refresh kernel truth
        kernel_chains = self.backend_impl.extract_chains(table_name)

        # ------------------------------------------------------------
        # 4. Flush chains (only strict/hybrid)
        # ------------------------------------------------------------
        if mode != "audit":
            for cname in activation_chains:
                if cname in kernel_chains:
                    r = self._safe_backend_call(
                        "flush_chain",
                        self.backend_impl.flush_chain,
                        table_name,
                        cname
                    )
                    if r.ok:
                        result.bump("flushed")
                    else:
                        result.add_error(r.errors[0])
        else:
            # audit mode → detect drift but do not flush
            pass

        # ------------------------------------------------------------
        # Final result
        # ------------------------------------------------------------
        return result
        
    def _should_update_nxt(self, nxt_path: Path, baseline_rules: list[Rule]) -> bool:
        """
        Decide whether nxt should be rewritten.

        nxt is rewritten ONLY when:
        - rules actually changed AND
        - the resulting ruleset differs from the existing nxt ruleset

        If nxt does not exist → must write it.
        """

        # If nxt missing → must write
        if not nxt_path.exists():
            return True

        # Load existing nxt rules (if load_nft is implemented)
        if self._nft_stub(self.backend_impl.load_nft):
            # Cannot load nxt → assume it needs updating
            return True

        nxt_rules = self.backend_impl.parse_nft_file(str(nxt_path))

        # Compare identity keys
        nxt_keys = {r.identity_key() for r in nxt_rules}
        baseline_keys = {r.identity_key() for r in baseline_rules}

        return nxt_keys != baseline_keys

    def compare_rules(self, canonical_rules: list[Rule], extracted_rules: list[Rule]) -> dict:
        """
        Compare canonical rules (from backend_registry) with extracted rules
        (from backend_impl.parse_rules()).

        Returns a structured diff:
        - missing: canonical rules not present in kernel
        - extra: kernel rules not present in canonical
        - changed: same rule_id but different semantics
        - ordering_drift: canonical order != kernel order
        """

        # Index by rule_id for fast lookup
        canonical_map = {r.rule_id: r for r in canonical_rules}
        extracted_map = {r.rule_id: r for r in extracted_rules}

        missing = []
        extra = []
        changed = []

        # 1. Missing or changed rules
        for rule_id, canonical_rule in canonical_map.items():
            backend_rule = extracted_map.get(rule_id)

            if backend_rule is None:
                missing.append(canonical_rule)
            else:
                if not canonical_rule.equals(backend_rule):
                    changed.append((canonical_rule, backend_rule))

        # 2. Extra rules
        for rule_id, backend_rule in extracted_map.items():
            if rule_id not in canonical_map:
                extra.append(backend_rule)

        # 3. Ordering drift
        canonical_order = [r.rule_id for r in canonical_rules]
        extracted_order = [r.rule_id for r in extracted_rules]
        ordering_drift = canonical_order != extracted_order

        return {
            "missing": missing,
            "extra": extra,
            "changed": changed,
            "ordering_drift": ordering_drift,
        }
    
    def enforce_rules(self, mode="strict"):
        """
        v3 rule enforcement with mode support:
        - strict  → enforce fully (semantic + ordering drift)
        - audit   → detect drift only, no kernel writes
        - hybrid  → enforce semantic drift, ignore ordering drift
        """

        result = EnforcementResult()

        # v3 supports exactly one table
        table_name, table = next(iter(self.backend_registry.items()))
        activation_rules = self.activation_map.get("rules", {})

        for chain_name, desired_rules in activation_rules.items():

            # kernel truth
            kernel_rules = self.backend_impl.extract_rules(table_name, chain_name)

            # Track whether we queued any changes
            queued_changes = False

            # ------------------------------------------------------------
            # 1. Add missing rules / replace semantic drift
            # ------------------------------------------------------------
            for idx, rule in enumerate(desired_rules):

                # Missing rule = semantic drift
                if idx >= len(kernel_rules):
                    if mode == "audit":
                        result.details.setdefault("missing_rules", {}).setdefault(chain_name, []).append(idx)
                        result.status = "DRIFT"
                        continue

                    # strict or hybrid → queue add
                    r = self._safe_backend_call(
                        "apply_rule",
                        self.backend_impl.apply_rule,
                        table_name,
                        chain_name,
                        rule,
                        idx
                    )
                    if not r.ok:
                        result.add_error(r.errors[0])
                    else:
                        queued_changes = True
                    continue

                # Drift detection
                semantic_drift = self.rule_drift(rule, kernel_rules[idx])

                if semantic_drift:
                    if mode == "audit":
                        result.details.setdefault("semantic_drift", {}).setdefault(chain_name, []).append(idx)
                        result.status = "DRIFT"
                        continue

                    # strict or hybrid → queue replace
                    r = self._safe_backend_call(
                        "replace_rule",
                        self.backend_impl.replace_rule,
                        table_name,
                        chain_name,
                        rule,
                        idx
                    )
                    if not r.ok:
                        result.add_error(r.errors[0])
                    else:
                        queued_changes = True

            # ------------------------------------------------------------
            # 2. Delete extra rules
            # ------------------------------------------------------------
            if len(kernel_rules) > len(desired_rules):
                for idx in range(len(desired_rules), len(kernel_rules)):

                    if mode == "audit":
                        result.details.setdefault("extra_rules", {}).setdefault(chain_name, []).append(idx)
                        result.status = "DRIFT"
                        continue

                    # strict or hybrid → queue delete
                    r = self._safe_backend_call(
                        "delete_rule",
                        self.backend_impl.delete_rule,
                        table_name,
                        chain_name,
                        idx
                    )
                    if not r.ok:
                        result.add_error(r.errors[0])
                    else:
                        queued_changes = True
            # ------------------------------------------------------------
            # 3. Ordering drift
            # ------------------------------------------------------------
            kernel_rules = self.backend_impl.extract_rules(table_name, chain_name)

            if len(kernel_rules) == len(desired_rules):

                # ordering drift = same semantics, different order
                ordering_drift = (
                    not any(self.rule_drift(desired_rules[i], kernel_rules[i])
                            for i in range(len(desired_rules)))
                    and desired_rules != kernel_rules
                )

                if ordering_drift:

                    if mode == "audit":
                        result.details.setdefault("ordering_drift", []).append(chain_name)
                        result.status = "DRIFT"
                        continue

                    if mode == "hybrid":
                        # hybrid ignores ordering drift
                        continue

                    # strict → rebuild chain
                    # delete all rules
                    for idx in reversed(range(len(kernel_rules))):
                        r = self._safe_backend_call(
                            "delete_rule",
                            self.backend_impl.delete_rule,
                            table_name,
                            chain_name,
                            idx
                        )
                        if not r.ok:
                            result.add_error(r.errors[0])

                    # re-add in correct order
                    for idx, rule in enumerate(desired_rules):
                        r = self._safe_backend_call(
                            "apply_rule",
                            self.backend_impl.apply_rule,
                            table_name,
                            chain_name,
                            rule,
                            idx
                        )
                        if not r.ok:
                            result.add_error(r.errors[0])

                    queued_changes = True

            # ------------------------------------------------------------
            # 4. Commit queued rule changes (strict/hybrid only)
            # ------------------------------------------------------------
            if queued_changes and mode != "audit":
                r = self._safe_backend_call("commit", self.backend_impl.commit)
                if r.ok:
                    result.bump("committed")
                else:
                    result.add_error(r.errors[0])

        return result

    def log_rule_drift(self, rule_cmp):
        """
        Emit lifecycle logs describing rule drift before enforcement.
        """

        # Missing rules
        for r in rule_cmp["missing"]:
            self.logger.lifecycle(f"[RULES] Missing rule: {r.rule_id}")

        # Extra rules
        for r in rule_cmp["extra"]:
            self.logger.lifecycle(f"[RULES] Extra rule: {r.rule_id}")

        # Changed rules
        for canonical, backend in rule_cmp["changed"]:
            self.logger.lifecycle(
                f"[RULES] Changed rule: {canonical.rule_id} "
                f"(backend differs from canonical)"
            )

        # Ordering drift
        if rule_cmp["ordering_drift"]:
            self.logger.lifecycle("[RULES] Ordering drift detected")

    def build_enforcement_summary(self, table_result, set_result, chain_result, rule_result):
        """
        Build a unified enforcement summary for the entire enforcement run.
        Accepts EnforcementResult objects and produces a clean summary dict.
        """

        # Determine if anything changed
        changed = (
            table_result.status != "NO_CHANGE" or
            set_result.status   != "NO_CHANGE" or
            chain_result.status != "NO_CHANGE" or
            rule_result.status  != "NO_CHANGE"
        )

        # Determine if any errors occurred
        errors = (
            table_result.errors +
            set_result.errors +
            chain_result.errors +
            rule_result.errors
        )

        return {
            "changed": changed,
            "errors": errors,
            "tables": {
                "status": table_result.status,
                "details": table_result.details,
                "errors": table_result.errors,
            },
            "sets": {
                "status": set_result.status,
                "details": set_result.details,
                "errors": set_result.errors,
            },
            "chains": {
                "status": chain_result.status,
                "details": chain_result.details,
                "errors": chain_result.errors,
            },
            "rules": {
                "status": rule_result.status,
                "details": rule_result.details,
                "errors": rule_result.errors,
            },
            "summary": {
                "tables_changed": table_result.status != "NO_CHANGE",
                "sets_changed":   set_result.status   != "NO_CHANGE",
                "chains_changed": chain_result.status != "NO_CHANGE",
                "rules_changed":  rule_result.status  != "NO_CHANGE",
            }
        }
    
    def _chain_drift(self, desired: dict, backend: dict) -> bool:
        """
        Compare desired chain metadata (activation_map) with backend metadata
        (backend_registry). Return True if drift is detected.
        """
        if not backend:
            # Chain exists in extracted list but we have no metadata → treat as drift
            return True

        fields = ("type", "hook", "priority")

        for key in fields:
            if desired.get(key) != backend.get(key):
                return True

        return False

    def _safe_backend_call(self, op_name, func, *args, **kwargs):
        """
        Unified wrapper for backend calls.
        Ensures:
        - No silent failures
        - Structured result propagation
        - Backend-agnostic error handling
        - Consistent logging format
        """
        try:
            result = func(*args, **kwargs)
            return {
                "ok": True,
                "result": result,
                "error": None,
                "op": op_name,
            }
        except Exception as e:
            msg = f"{op_name} failed: {e}"
            return {
                "ok": False,
                "result": None,
                "error": msg,
                "op": op_name,
            }
    safe = _safe_backend_call