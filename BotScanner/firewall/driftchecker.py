"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-01
Modified: 2026-01-29
File: BotScanner/firewall/driftchecker.py
Description: DriftChecker: Pure comparison logic for firewall drift (v2)
"""
# System Libraries
import json
import difflib
from typing import Dict, Any
# Project Libraries
from .rule import Rule
from .baseline import BaseLine
from .classifier import DriftClassifier, DriftEntry

class DriftChecker:
    """
    v3 DriftChecker:
    - Operates on canonical Rule objects (dicts with stable fields)
    - Produces flat dotted-path diffs
    - Handles baseline-missing behavior
    - Emits deterministic structured + text diffs
    """

    def __init__(self, cfg: dict, lgr_cfg: dict, baseline_manager=None):
        self.cfg = cfg
        self.logger = lgr_cfg["factory"].get_logger("driftchecker")
        self.classifier = DriftClassifier()
        self.baseline_manager = baseline_manager

    # ------------------------------------------------------------
    # v3: Baseline handling
    # ------------------------------------------------------------
    def _handle_missing_baseline(self, owner: str, backend_name: str, current: dict):
        self.logger.info("[DRIFT] No baseline found — creating new baseline")
        if self.baseline_manager:
            self.baseline_manager.save_backend_baseline(owner, backend_name, current)
        return {
            "drift": "NO_BASELINE",
            "structured": {},
            "summary": [],
            "text_diff": ""
        }

    # ------------------------------------------------------------
    # v3: Canonical diff engine
    # ------------------------------------------------------------
    def _canonical_diff(self, baseline: Any, current: Any, path="") -> Dict[str, dict]:
        """
        v3 canonical diff:
        - Field-by-field comparison
        - Dicts recurse
        - Lists compare by membership
        - Scalars compare directly
        - Output is flat dotted-path → diff object
        """
        diffs = {}

        # Case 1: both dicts
        if isinstance(baseline, dict) and isinstance(current, dict):
            keys = set(baseline) | set(current)
            for k in keys:
                new_path = f"{path}.{k}" if path else k

                if k not in baseline:
                    diffs[new_path] = {"from": None, "to": current[k]}
                elif k not in current:
                    diffs[new_path] = {"from": baseline[k], "to": None}
                else:
                    diffs.update(self._canonical_diff(baseline[k], current[k], new_path))
            return diffs

        # Case 2: lists
        if isinstance(baseline, list) and isinstance(current, list):
            added = [x for x in current if x not in baseline]
            removed = [x for x in baseline if x not in current]
            if added or removed:
                diffs[path] = {"from": removed, "to": added}
            return diffs

        # Case 3: scalar mismatch
        if baseline != current:
            diffs[path] = {"from": baseline, "to": current}

        return diffs

    # ------------------------------------------------------------
    # v3: Flattening helpers (kept from v2, simplified)
    # ------------------------------------------------------------
    @staticmethod
    def _prune_empty(diffs: Dict[str, dict]) -> Dict[str, dict]:
        return {k: v for k, v in diffs.items() if v.get("from") != v.get("to")}

    # ------------------------------------------------------------
    # v3: Text diff (unchanged)
    # ------------------------------------------------------------
    def _generate_text_diff(self, baseline_rules: list, current_rules: list) -> str:
        """
        v3: Generate a unified text diff between two lists of Rule objects.
        Converts Rule objects to JSON-safe dicts before diffing.
        """

        # Convert Rule objects → JSON-safe dicts
        baseline_json = json.dumps(
            [r.to_dict() for r in baseline_rules],
            sort_keys=True,
            indent=2
        )

        current_json = json.dumps(
            [r.to_dict() for r in current_rules],
            sort_keys=True,
            indent=2
        )

        # Produce unified diff
        return "\n".join(
            difflib.unified_diff(
                baseline_json.splitlines(),
                current_json.splitlines(),
                fromfile="baseline.json",
                tofile="current.json",
                lineterm=""
            )
        )
    
    # ------------------------------------------------------------
    # v3: Main entry point
    # ------------------------------------------------------------
    def run_drift(self, owner: str, backend_name: str, baseline: dict, current: dict) -> dict:
        """
        v3 drift:
        - Handles missing baseline
        - Canonical diff engine
        - Classification
        - Deterministic output
        """

        # Missing baseline → create + skip drift
        if baseline is None:
            return self._handle_missing_baseline(owner, backend_name, current)

        # Canonical diff
        diffs = self._canonical_diff(baseline, current)
        diffs = self._prune_empty(diffs)

        if not diffs:
            self.logger.debug("[DRIFT] No drift detected")
            return {"drift": "NO_DRIFT", "structured": {}, "text_diff": ""}

        self.logger.debug("[DRIFT] Drift detected")

        # Text diff
        text_diff = self._generate_text_diff(baseline, current)

        # Classification


        backend_name = self.cfg.get("backend", "unknown")
        classified = {"critical": [], "noncritical": [], "benign": []}

        for dotted_path, diff_obj in diffs.items():
            entry = DriftEntry(
                backend=backend_name,
                path=dotted_path,
                expected=diff_obj["from"],
                actual=diff_obj["to"],
            )
            result = self.classifier.classify(entry)
            classified[result["type"]].append(result)
        classified_dict = self._entries_to_dicts(classified)

        summary = self._generate_summary(diffs)
       
        return {
            "drift": "DRIFT",
            "structured": classified_dict,
            "text_diff": text_diff,
            "summary": summary
        }

    def _generate_summary(self, diffs: dict) -> list[dict]:
        summary = []

        for path, change in diffs.items():
            old = change.get("from")
            new = change.get("to")

            # Convert Rule objects → dicts
            if hasattr(old, "to_dict"):
                old = old.to_dict()
            if hasattr(new, "to_dict"):
                new = new.to_dict()

            if old is None:
                summary.append({
                    "path": path,
                    "type": "added",
                    "value": new,
                })
            elif new is None:
                summary.append({
                    "path": path,
                    "type": "removed",
                    "value": old,
                })
            else:
                summary.append({
                    "path": path,
                    "type": "changed",
                    "from": old,
                    "to": new,
                })

        return summary

    def _entries_to_dicts(self, entries_by_type):
        out = {}
        for key, items in entries_by_type.items():
            out[key] = []
            for item in items:
                expected = item.get("expected")
                actual = item.get("actual")

                # Single Rule → dict
                if hasattr(expected, "to_dict"):
                    expected = expected.to_dict()
                if hasattr(actual, "to_dict"):
                    actual = actual.to_dict()

                # List[Rule] → list[dict]
                if isinstance(expected, list):
                    expected = [
                        r.to_dict() if hasattr(r, "to_dict") else r
                        for r in expected
                    ]
                if isinstance(actual, list):
                    actual = [
                        r.to_dict() if hasattr(r, "to_dict") else r
                        for r in actual
                    ]

                out[key].append({
                    "backend": item.get("backend"),
                    "path": item.get("path"),
                    "expected": expected,
                    "actual": actual,
                    "type": item.get("type"),
                    "reason": item.get("reason"),
                })
        return out

    def _detect_drift(self, baseline_rules: list[Rule], kernel_rules: list[Rule]) -> dict:
        """
        Detect semantic drift between baseline and kernel rules.

        Drift is defined as:
            - Rules present in kernel but missing from baseline  (ADDED)
            - Rules present in baseline but missing from kernel  (REMOVED)

        Ordering does not matter.
        Identity keys define semantic equality.

        Returns a structured drift report:
            {
                "added":   [Rule, Rule, ...],
                "removed": [Rule, Rule, ...],
                "has_drift": bool
            }
        """

        # Convert to identity-key sets
        baseline_keys = {r.identity_key(): r for r in baseline_rules}
        kernel_keys   = {r.identity_key(): r for r in kernel_rules}

        # Compute semantic drift
        added_keys   = set(kernel_keys.keys())   - set(baseline_keys.keys())
        removed_keys = set(baseline_keys.keys()) - set(kernel_keys.keys())

        added_rules   = [kernel_keys[k] for k in added_keys]
        removed_rules = [baseline_keys[k] for k in removed_keys]

        has_drift = bool(added_rules or removed_rules)

        return {
            "added": added_rules,
            "removed": removed_rules,
            "has_drift": has_drift,
        }
             
    def _classify_drift(self, drift: dict) -> dict:
        """
        Classify drift into critical, noncritical, and benign categories.

        Drift classification rules (v3 defaults):
        - Any DROP/REJECT rule missing from kernel = CRITICAL
        - Any ACCEPT rule added to kernel = CRITICAL
        - Any rule in INPUT/FORWARD chains that changes traffic flow = CRITICAL
        - Rules in OUTPUT chain are usually NONCRITICAL unless DROP/REJECT
        - Cosmetic differences (comments, ordering) = BENIGN
        - Unknown chains default to NONCRITICAL

        Returns:
            {
                "critical":   [Rule, Rule],
                "noncritical":[Rule],
                "benign":     [Rule],
                "has_critical": bool
            }
        """

        critical = []
        noncritical = []
        benign = []

        # Helper to classify a single rule
        def classify_rule(rule: Rule, direction: str):
            """
            direction = "added" or "removed"
            """

            # 1. Missing DROP/REJECT rules are critical
            if direction == "removed" and rule.action in ("drop", "reject"):
                critical.append(rule)
                return

            # 2. Added ACCEPT rules are critical
            if direction == "added" and rule.action == "accept":
                critical.append(rule)
                return

            # 3. INPUT/FORWARD chains are more sensitive
            if rule.chain in ("input", "forward"):
                # Missing ACCEPT is noncritical (traffic becomes more restrictive)
                if direction == "removed" and rule.action == "accept":
                    noncritical.append(rule)
                    return

                # Added DROP/REJECT is noncritical (more restrictive)
                if direction == "added" and rule.action in ("drop", "reject"):
                    noncritical.append(rule)
                    return

                # Anything else is critical
                critical.append(rule)
                return

            # 4. OUTPUT chain is less sensitive
            if rule.chain == "output":
                # Missing DROP/REJECT is critical (traffic becomes more permissive)
                if direction == "removed" and rule.action in ("drop", "reject"):
                    critical.append(rule)
                    return

                # Added ACCEPT is critical (more permissive)
                if direction == "added" and rule.action == "accept":
                    critical.append(rule)
                    return

                # Everything else is noncritical
                noncritical.append(rule)
                return

            # 5. Unknown chains default to noncritical
            noncritical.append(rule)

        # Classify added rules
        for rule in drift["added"]:
            classify_rule(rule, "added")

        # Classify removed rules
        for rule in drift["removed"]:
            classify_rule(rule, "removed")

        return {
            "critical": critical,
            "noncritical": noncritical,
            "benign": benign,
            "has_critical": bool(critical),
        }             
    
