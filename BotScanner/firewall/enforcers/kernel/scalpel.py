"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-14
Modified: 2026-02-14
File: BotScanner/firewall/enforcers/scalpel.py
Description: Describe the purpose of this file
"""

# System Libraries
from typing import Iterable
# Project Libraries

class KernelScalpel:
    """
    Runtime enforcement driver (the 'scalpel').

    Responsibilities:
    - Ensure kernel is in a valid, enforceable state
    - Delegate to Hammer when kernel/baseline are invalid
    - Perform element-only updates (e.g., botblock set)
    - Refresh baseline after runtime updates

    This class does NOT:
    - Build activation_map or element_map
    - Build canonical tables/sets/chains/rules
    - Perform full bootstrap or nxt recovery logic itself
      (it delegates that to Hammer)
    """

    def __init__(self, cfg, lgr_cfg, backend_enforcer, hammer):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        self.backend = backend_enforcer
        self.hammer = hammer

        factory = lgr_cfg.get("factory")
        self.logger = factory.get_logger("scalpel") if factory else None

    # ------------------------------------------------------------
    # Public entry point for apache/log-driven updates
    # ------------------------------------------------------------
    def update_botblock_from_logs(self, new_elements: Iterable[str]) -> dict:
        """
        Called by apache/log parsing pipeline.

        Flow:
        - Ensure kernel is in a valid state (baseline + kernel aligned)
        - Update botblock elements
        - Refresh baseline from kernel
        """
        self.logger.lifecycle("[SCALPEL] Starting runtime botblock update")

        # 1. Ensure kernel is valid; delegate to Hammer if needed
        self.ensure_kernel_valid()

        # 2. Update botblock elements via backend enforcer
        self._update_botblock_elements(set(new_elements))

        # 3. Refresh baseline from kernel
        rules = self.backend.parse_kernel_rules()
        self.backend.save_kernel_baseline(rules)

        self.logger.lifecycle("[SCALPEL] Runtime botblock update complete")

        return {
            "status": "RUNTIME_UPDATE_COMPLETE",
            "elements_count": len(set(new_elements)),
        }

    # ------------------------------------------------------------
    # Kernel validity / drift handling
    # ------------------------------------------------------------
    def ensure_kernel_valid(self) -> None:
        """
        Ensure kernel rules are in a valid state for runtime updates.

        If:
        - no baseline, or
        - no kernel rules, or
        - drift detected between baseline and kernel

        then delegate to Hammer for a full enforcement pass.
        """
        baseline = self.backend.load_kernel_baseline()
        kernel_rules = self.backend.parse_kernel_rules()

        if not baseline:
            self.logger.lifecycle("[SCALPEL] No baseline; delegating to Hammer")
            self._delegate_full_enforcement()
            return

        if not kernel_rules:
            self.logger.lifecycle("[SCALPEL] No kernel rules; delegating to Hammer")
            self._delegate_full_enforcement()
            return

        if self._rules_drifted(baseline, kernel_rules):
            self.logger.lifecycle("[SCALPEL] Drift detected; delegating to Hammer")
            self._delegate_full_enforcement()
            return

        self.logger.lifecycle("[SCALPEL] Kernel is valid; proceeding with runtime update")

    def _rules_drifted(self, baseline, kernel_rules) -> bool:
        """
        Placeholder for your real drift logic.

        For now, a simple inequality check.
        You can later plug in a canonical comparison, hashing, etc.
        """
        return baseline != kernel_rules

    def _delegate_full_enforcement(self) -> None:
        """
        Hook for calling Hammer when a full rebuild is required.

        NOTE:
        - This method assumes the orchestrator (or caller) is responsible
          for providing canonical_* structures to Hammer.
        - For now, this is a seam: you can wire it once your canonical
          surfaces are fully defined.
        """
        # You have two options for wiring this:
        # 1. Pass canonical_* into Scalpel.update_botblock_from_logs(...)
        #    and thread them through to this method.
        # 2. Have the orchestrator call Hammer directly when it detects
        #    that a runtime update requires a full rebuild.
        #
        # For now, we just log the intent.
        self.logger.lifecycle(
            "[SCALPEL] Full enforcement required; caller must invoke Hammer.enforce(...) "
            "with canonical tables/sets/chains/rules"
        )
        # Example shape (to be wired later):
        # self.hammer.enforce(canonical_tables, canonical_sets,
        #                     canonical_chains, canonical_rules)

    # ------------------------------------------------------------
    # Botblock element update
    # ------------------------------------------------------------
    def _update_botblock_elements(self, elements: set[str]) -> None:
        """
        Backend-agnostic element update.

        Delegates to backend enforcer to sync the botblock set.
        """
        self.logger.lifecycle(
            f"[SCALPEL] Updating botblock elements; count={len(elements)}"
        )
        # Assumes backend implements a method like this; you can rename
        # or adapt to your actual backend interface.
        self.backend.update_botblock_elements(elements)