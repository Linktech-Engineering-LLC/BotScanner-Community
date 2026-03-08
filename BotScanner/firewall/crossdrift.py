"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-09
Modified: 2026-01-28
File: BotScanner/firewall/crossdrift.py
Description: Backend-agnostic cross-drift comparison between all active firewall backends.
"""
# System Libraries
# Project Libraries
from ..firewall.common import (
    semantic_diff
)
from .classifier import DriftClassifier

class BackendInactiveError(Exception):
    """Raised when a backend baseline cannot be loaded (inactive backend)."""

    def __init__(self, backend: str, reason: str = None):
        self.backend = backend
        self.reason = reason or "Unknown"
        super().__init__(f"Backend '{backend}' inactive: {self.reason}")


class CrossDriftChecker:
    """
    v3 Cross‑Drift Checker
    ----------------------
    Performs canonical semantic structural diff between every pair of active
    backends. Produces a v3 drift payload including:

        - structured drift (classified)
        - summary
        - text diff

    This class does NOT:
        - load baselines
        - write drift files
        - handle rotation or symlinks
        - depend on backend-specific canonicalization
        - support multiple comparison modes (v2 feature removed)

    DriftWriter handles all artifact writing.
    """

    def __init__(self, cfg: dict, lgr_cfg: dict, backend_registry: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        self.logger = lgr_cfg["factory"].get_logger("crossdrift")
        self.backend_registry = backend_registry
        self.classifier = DriftClassifier()

    # ----------------------------------------------------------------------
    # Backend state loading
    # ----------------------------------------------------------------------

    def _load_rules(self, backend_name: str, backend) -> list:
        """
        v3: Backends must expose canonical Rule objects via backend.parse_rules().
        Raises BackendInactiveError if parse fails.
        """
        try:
            rules = backend.parse_rules()
        except Exception as e:
            raise BackendInactiveError(backend_name, f"parse_rules() failed: {e}")

        if not rules:
            raise BackendInactiveError(backend_name, "No canonical rules returned")

        return rules

    # ----------------------------------------------------------------------
    # Pairwise comparison
    # ----------------------------------------------------------------------

    def _compare_pair(self, a_name: str, a_rules: list, b_name: str, b_rules: list) -> dict:
        """
        v3: Canonical semantic structural diff between two rule sets.
        Produces a v3 drift payload for this pair.
        """

        # 1. Canonical diff
        raw_diff = semantic_diff(a_rules, b_rules)

        # 2. Classification
        classified = self.classifier.classify(raw_diff)

        # 3. Summary
        summary = self.classifier.summarize(classified)

        # 4. Text diff (human-readable)
        text_diff = generate_text_diff(a_name, b_name, a_rules, b_rules)

        return {
            "structured": classified,
            "summary": summary,
            "text_diff": text_diff,
        }

    # ----------------------------------------------------------------------
    # Main entry point
    # ----------------------------------------------------------------------

    def compare(self) -> dict:
        """
        v3: Perform canonical cross‑drift across all active backends.
        Returns a v3 drift payload:

            {
                "cross_drift": "DRIFT" | "NO_DRIFT",
                "pairs": { "a:b": {structured, summary, text_diff}, ... },
                "summary": [...]
            }
        """

        active = self.backend_registry
        names = sorted(active.keys())

        if len(names) < 2:
            self.logger.info("Cross‑drift: fewer than two active backends.")
            return {
                "cross_drift": "NO_DRIFT",
                "pairs": {},
                "summary": [],
            }

        # Load canonical rules for each backend
        rules_map = {}
        for name in names:
            backend = active[name]
            try:
                rules_map[name] = self._load_rules(name, backend)
            except BackendInactiveError as e:
                self.logger.warning(f"[CROSSDRIFT] Skipping inactive backend {name}: {e}")
                continue
        if len(rules_map) < 2:
            return None
        
        # Pairwise comparisons
        pairs_result = {}

        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                a_name = names[i]
                b_name = names[j]

                if a_name not in rules_map or b_name not in rules_map:
                    continue

                a_rules = rules_map[a_name]
                b_rules = rules_map[b_name]

                pair_key = f"{a_name}:{b_name}"
                pairs_result[pair_key] = self._compare_pair(a_name, a_rules, b_name, b_rules)

        # Determine overall drift
        any_drift = any(
            pair["structured"]["critical"] or
            pair["structured"]["noncritical"]
            for pair in pairs_result.values()
        )

        # Aggregate summary across all pairs
        overall_summary = self._summarize_all_pairs(pairs_result)

        return {
            "cross_drift": "DRIFT" if any_drift else "NO_DRIFT",
            "pairs": pairs_result,
            "summary": overall_summary,
        }

    # ----------------------------------------------------------------------
    # Summary aggregation
    # ----------------------------------------------------------------------

    def _summarize_all_pairs(self, pairs: dict) -> list:
        """
        Combine summaries from all pairwise comparisons into a single list.
        """
        combined = []
        for pair_key, payload in pairs.items():
            for entry in payload["summary"]:
                combined.append({
                    "pair": pair_key,
                    **entry
                })
        return combined        
