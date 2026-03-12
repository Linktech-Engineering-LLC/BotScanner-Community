"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-01
Modified: 2026-03-12
File: BotScanner/firewall/orchestrator.py
Description: Describe the purpose of this file
"""
# System Libraries
# Project Libraries
from BotScanner.net.discovery import NetDiscovery
from .canonical.builder import CanonicalBuilder
from .enforcers.builder import ActivationMapBuilder
from .enforcers.helpers.detect import (
    select_backends,
    ManagerBackend,
    KernelBackend
)
from .enforcers.kernel.nftables import NftablesEnforcer
from .enforcers.kernel.hammer import KernelHammer
from .enforcers.kernel.scalpel import KernelScalpel
from .enforcers.manager.firewalld import FirewalldEnforcer
from .enforcers.manager.ufw import UfwEnforcer
from .common import (
    get_backend_owner, 
    verify_checksum, 
    load_firewall_cfg
)
from .backend.factory import BackendFactory
from .baseline import BaseLine
from .driftchecker import DriftChecker
from .driftwriter import DriftWriter
from .crossdrift import CrossDriftChecker, BackendInactiveError
from .sets.builder import SetElementBuilder
from .rule import Rule
from ..utils import Flags

class InvalidOwnerError(Exception):
    pass
class FirewallOrchestrator:
    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        self.logger_factory = lgr_cfg.get("factory")
        self.logger = self.logger_factory.get_logger(module="orchestrator")
        self.active_flags = self.lgr_cfg.get("active_flags", [])
        self.sudo_password = self.cfg.get("secrets", {}).get("sudo_pass")
        mask_hex = lgr_cfg.get("flags_mask")
        if mask_hex is None:
            mask = 0
        else:
            mask = int(mask_hex, 16)
        self.flags = Flags.from_mask(mask)
        self.backend_factory = BackendFactory(self.cfg, self.lgr_cfg)
        self.baseline_store = BaseLine(self.cfg, self.lgr_cfg)
        self.drift_checker = DriftChecker(
            cfg=self.cfg,
            lgr_cfg=self.lgr_cfg,
            baseline_manager=self.baseline_store
        )
        self.drift_writer = DriftWriter(self.cfg, self.lgr_cfg)
        self.backend_instances = self._define_registry()

    def _define_registry(self):
        # 1. Detect real system backends
        selection = select_backends(self.sudo_password)
        # 2. Convert selection → backend names
        active_backend_names = self.selection_to_backend_names(selection)

        backend_instances = {}

        for name in active_backend_names:
            try:
                instance = self.backend_factory.get_backend(name)
                backend_instances[name] = instance
            except Exception as e:
                self.logger.warning(f"[ORCH] failed to initialize backend '{name}': {e}")

        return backend_instances

    def run(self):
        self.selection = select_backends(self.sudo_password)
        for name, backend in self.backend_instances.items():
            owner = self.get_backend_owner(name)

            # FIREWALL_STATUS
            if self.flags & Flags.BitmapFlags.FIREWALL_STATUS:
                self._run_status_single(name)

            # FIREWALL_BASE
            if self.flags & Flags.BitmapFlags.FIREWALL_BASE:
                self._run_baseline_single(owner, name)

            # FIREWALL_DRIFT
            if self.flags & Flags.BitmapFlags.FIREWALL_DRIFT:
                self._run_drift(owner, name)

        # FIREWALL_CROSS_DRIFT
        if self.flags & Flags.BitmapFlags.CROSS_DRIFT:
            self.run_cross_drift()

        # 2. Build runtime discovery
        self.cfg["runtime"] = NetDiscovery.build_runtime(self.logger)

        # 3. Build activation map (zones → sets)
        activation_result = ActivationMapBuilder(
            self.cfg,
            self.lgr_cfg,
        ).build()

        # 3a. Validate activation map
        if not activation_result.get("success"):
            self.logger.error(
                f"[ORCH] Activation map build failed: "
                f"{activation_result.get('error')}"
            )
            return

        self.activation_map = activation_result["activation_map"]

        seb = SetElementBuilder(self.cfg, self.activation_map, self.logger)
        self.element_map = seb.build()
        
        builder = CanonicalBuilder(
            yaml_cfg=self.cfg,
            activation_map=self.activation_map,
            element_map=self.element_map,
        )
        self.canonical = builder.build()

        # 4. Enforcement (global)
        if self.flags & Flags.BitmapFlags.ENFORCE_KERNEL:
            self.run_kernel_hammer()

        if self.flags & Flags.BitmapFlags.ENFORCE_MANAGER:
            if self.selection.manager == ManagerBackend.NONE:
                self.logger.error("[ORCH] No manager backend available for enforcement")
            else:
                self._run_manager_enforcement()
                self.logger.lifecycle("[ORCH] Completed firewall orchestration run")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def _run_status_single(self, backend_name: str):
        # Get the backend instance (kernel or manager)
        backend = self.backend_factory.get_backend(backend_name)

        # Ask the backend itself whether it is online
        online = backend.status()

        self.logger.info(
            f"[ORCH] Backend '{backend_name}' Status: "
            f"{'Online' if online else 'Offline'}"
        )
    
    # ------------------------------------------------------------------
    # Baseline capture
    # ------------------------------------------------------------------
    def _run_baseline_single(self, owner: str, backend_name: str):
        self.logger.lifecycle(
            f"[ORCH] Capturing baseline for backend='{backend_name}' owner='{owner}'"
        )

        backend = self.backend_factory.get_backend(backend_name)
        # Runtime health check
        if not backend.status():
            self.logger.error(
                f"[ORCH] Backend '{backend_name}' is not online or not responding"
            )
            return

        # Parsing Baseline based on Rules
        current = backend.parse_rules()
        if not current:
            self.logger.info(
                f"[ORCH] Backend '{backend_name}' returned no rules; creating empty baseline and continuing"
            )

        # Save backend baseline JSON/TXT/checksum
        paths = self.baseline_store.save_backend_baseline(owner, backend_name, current)

        # Verify checksum if present
        if "json" in paths and "checksum" in paths:
            if verify_checksum(paths["json"], paths["checksum"]):
                self.logger.lifecycle(
                    f"[ORCH] Baseline verified OK for backend='{backend_name}' owner='{owner}'"
                )
            else:
                self.logger.error(
                    f"[ORCH] Baseline verification FAILED for backend='{backend_name}' owner='{owner}'"
                )

        # Log artifacts
        log_parts = []
        for key in ("json", "txt", "checksum"):
            if key in paths:
                log_parts.append(f"{key.upper()}={str(paths[key])}")

        self.logger.lifecycle(
            f"[ORCH] Baseline saved for backend='{backend_name}' owner='{owner}' "
            + ", ".join(log_parts)
        )
    
    # ------------------------------------------------------------------
    # v2 Drift Pipeline
    # ------------------------------------------------------------------
    def _run_drift(self, owner: str, backend_name: str):
        self.logger.lifecycle(
            f"[ORCH] Running drift for backend='{backend_name}' owner='{owner}'"
        )

        backend = self.backend_factory.get_backend(backend_name)

        # Runtime health check
        if not backend.status():
            self.logger.error(
                f"[ORCH] Backend '{backend_name}' is not online or not responding"
            )
            return

        # Capture current state
        current = backend.parse_rules()
        if current is None:
            self.logger.error(
                f"[ORCH] Backend '{backend_name}' failed to return canonical rules"
            )
            return

        if current == {}:
            self.logger.info(
                f"[ORCH] Backend '{backend_name}' returned no rules; treating as empty rule set"
            )

        # Load baseline (may be None — v3 DriftChecker handles this)
        baseline = self.baseline_store.load_backend_baseline(owner, backend_name)

        # Run drift check (v3 handles missing baseline)
        drift = self.drift_checker.run_drift(owner, backend_name, baseline, current)
        drift_type = drift.get("drift")

        # Case 1: No baseline → v3 created it → skip drift this cycle
        if drift_type == "NO_BASELINE":
            self.logger.info(
                f"[ORCH] Baseline created for backend='{backend_name}', skipping drift this cycle"
            )
            return

        # Case 2: No drift
        if drift_type == "NO_DRIFT":
            self.logger.info(f"[ORCH] No drift detected for backend='{backend_name}'")
            return

        # Case 3: Drift detected
        classified = drift.get("structured", {})
        if not any(classified.values()):
            self.logger.info(f"[ORCH] No drift detected for backend='{backend_name}'")
            return

        # Write drift results
        self.drift_writer.write_drift(owner, backend_name, classified)

        self.logger.lifecycle(
            f"[ORCH] Drift run complete for backend='{backend_name}' owner='{owner}'"
        )
            
    def run_cross_drift(self):
        self.logger.info("[ORCH] Starting cross-drift check")

        checker = CrossDriftChecker(
            self.cfg,
            self.lgr_cfg,
            backend_registry=self.backend_instances,
        )

        try:
            diffs = checker.compare()
        except BackendInactiveError as e:
            self.logger.warning(f"[ORCH] Cross-drift aborted due to inactive backend: {e}")
            return None
        except Exception as e:
            self.logger.error(f"[ORCH] Cross-drift failed unexpectedly: {e}")
            return None

        # Case 1: No comparison possible (fewer than 2 active backends)
        if diffs is None:
            self.logger.info("[ORCH] Cross-drift skipped: insufficient active backends")
            return None

        # Case 2: Comparison possible but no differences
        if not diffs:
            self.logger.info("[ORCH] No cross-drift detected")
            return diffs

        # Case 3: Real differences
        self.logger.info("[ORCH] Cross-drift differences detected, writing drift file")
        writer = DriftWriter(self.cfg, self.lgr_cfg)
        writer.write_drift(None, "cross", diffs)
        return diffs

    def run_kernel_hammer(self):
        """
        v3 full enforcement entry point.
        - Build canonical rule structures
        - Instantiate backend enforcer
        - Instantiate Hammer
        - Run full enforcement
        """

        # 2. Select backend enforcer
        if self.selection.kernel == KernelBackend.NFTABLES:
            backend_enforcer = NftablesEnforcer(
                cfg=self.cfg,
                lgr_cfg=self.lgr_cfg,
            )

        else:
            self.logger.error("[ORCH] Unknown kernel backend; cannot enforce")
            return

        # 3. Instantiate Hammer
        hammer = KernelHammer(
            cfg=self.cfg,
            lgr_cfg=self.lgr_cfg,
            backend=backend_enforcer,
            activation_map=self.activation_map,
            element_map=self.element_map,
            canonical=self.canonical
        )

        # 4. Run full enforcement
        return hammer.enforce()

    def _run_manager_enforcement(self):
        # ------------------------------------------------------------------
        # Manager Enforcement (Disabled for v3)
        #
        # Manager-side enforcement (firewalld, ufw, etc.) is intentionally
        # disabled for the v3 release. The v3 architecture provides a fully
        # normalized, backend-agnostic kernel enforcement pipeline, but the
        # equivalent manager pipeline has not yet been implemented.
        #
        # This guard prevents accidental activation of manager enforcement,
        # which would currently produce inconsistent behavior, incomplete
        # normalization, and incorrect drift/cross-drift results.
        #
        # Future maintainers:
        #   - Remove this guard ONLY after implementing the full v4 manager
        #     normalization pipeline (sets, chains, rules, activation, drift).
        #   - Simply enabling the flag without the full pipeline will break
        #     enforcement semantics.
        #
        # If a user enables ENFORCE_MANAGER in this version, we fail safe.
        # ------------------------------------------------------------------
        if self.flags & Flags.BitmapFlags.ENFORCE_MANAGER:
            self.logger.error("[ORCH] Manager enforcement backend unavailable at this time")
            return

        # No manager backend available
        if self.selection.manager == ManagerBackend.NONE:
            self.logger.error("[ORCH] No manager backend available for enforcement")
            return

        # FIREWALLD enforcement
        if self.selection.manager == ManagerBackend.FIREWALLD:
            self.logger.lifecycle("[ORCH] Running firewalld manager enforcement")
            enforcer = FirewalldEnforcer(
                self.cfg,
                self.lgr_cfg,
                backend="firewalld"
            )
            enforcer.run(self.activation_map, mode="strict")
            return

        # UFW enforcement
        if self.selection.manager == ManagerBackend.UFW:
            self.logger.lifecycle("[ORCH] Running UFW manager enforcement")
            enforcer = UfwEnforcer(
                self.cfg,
                self.lgr_cfg,
                backend="ufw"
            )
            enforcer.run(self.activation_map, mode="strict")
            return

        # Unknown manager backend
        self.logger.error(
            f"[ORCH] Manager backend '{self.selection.manager.value}' not supported for enforcement"
        )
    
    def selection_to_backend_names(self, selection) -> list[str]:
        names = []

        # Manager backend
        if selection.manager == ManagerBackend.FIREWALLD:
            names.append("firewalld")
        elif selection.manager == ManagerBackend.UFW:
            names.append("ufw")

        # Kernel backend
        if selection.kernel == KernelBackend.NFTABLES:
            names.append("nftables")

        return names

    def get_backend_owner(self, backend_name: str) -> str:
        declared_owner = None
        embedded_owner = None

        firewall_cfg = self.cfg.get("firewall", {})
        backends_section = firewall_cfg.get("backends", {})

        # Method 1: Owner from backends: section
        for owner, data in backends_section.items():
            priority = data.get("priority", [])
            if backend_name in priority:
                declared_owner = owner
                break

        # Method 2: Owner from backend definition
        backend_def = backends_section.get(backend_name, {})
        if "owner" in backend_def:
            embedded_owner = backend_def["owner"]

        # Case 1: Both exist and match
        if declared_owner and embedded_owner:
            if declared_owner == embedded_owner:
                self.logger.debug(
                    f"[ORCH] Owner for backend '{backend_name}' resolved: '{declared_owner}'"
                )
                return declared_owner
            else:
                # Case 2: Both exist but differ → fatal
                self.logger.error(
                    f"[ORCH] Owner mismatch for backend '{backend_name}': "
                    f"declared='{declared_owner}', embedded='{embedded_owner}'"
                )
                raise InvalidOwnerError(
                    f"Owner mismatch for backend '{backend_name}'"
                )

        # Case 3: Only declared owner exists → warn but accept
        if declared_owner:
            self.logger.warning(
                f"[ORCH] Backend '{backend_name}' has declared owner '{declared_owner}' "
                f"but no embedded owner in backend definition"
            )
            return declared_owner

        # Case 4: Only embedded owner exists → warn but accept
        if embedded_owner:
            self.logger.warning(
                f"[ORCH] Backend '{backend_name}' has embedded owner '{embedded_owner}' "
                f"but is not listed under backends: section"
            )
            return embedded_owner

        # Case 5: Neither exists → fatal
        self.logger.error(
            f"[ORCH] No owner found for backend '{backend_name}' in either "
            f"backends: section or backend definition"
        )
        raise InvalidOwnerError(
            f"No owner found for backend '{backend_name}'"
        )
 
