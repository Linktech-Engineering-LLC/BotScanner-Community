"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-21
Modified: 2026-01-28
File: BotScanner/firewall/classifier.py
Description: BotScanner Firewall Drift Classifier
Deterministic, backend‑agnostic drift categorization.

Categories:
  - critical
  - noncritical
  - benign

"""
# System Libraries
from dataclasses import dataclass
from typing import Any, Dict, Optional
# Project Libraries

@dataclass
class DriftEntry:
    """Represents a single canonical drift item before classification."""
    backend: str
    path: str
    expected: Any
    actual: Any
    reason: Optional[str] = None   # explicit override


class DriftClassifier:
    """
    v3 DriftClassifier:
    - Works with canonical diffs (always {from, to})
    - Classifies drift into critical, noncritical, or benign
    - Supports explicit overrides
    """

    BENIGN_PATTERNS = [
        "handle",
        "timestamp",
        "counters",
        "uid", "gid",
        "revision",
    ]

    CRITICAL_PATTERNS = [
        "chains",
        "sets",
        "policy",
        "trusted",
        "nat",
        "table",
    ]

    NONCRITICAL_PATTERNS = [
        "order",
        "comment",
        "description",
    ]

    def classify(self, entry: DriftEntry) -> Dict[str, Any]:
        """
        Classify a canonical drift entry.
        """

        # Rule 4 — Explicit override
        if entry.reason:
            return self._override(entry)

        # Rule 5 — Canonical diff indicates no change
        if entry.expected == entry.actual:
            return self._benign(entry, "canonical diff indicates no change")

        # Rule 3 — Backend noise
        if self._matches(entry.path, self.BENIGN_PATTERNS):
            return self._benign(entry, "benign backend noise")

        # Rule 1 — Security-first
        if self._matches(entry.path, self.CRITICAL_PATTERNS):
            return self._critical(entry, "security-relevant drift")

        # Rule 2 — Policy fidelity
        if self._matches(entry.path, self.NONCRITICAL_PATTERNS):
            return self._noncritical(entry, "policy-adjacent drift")

        # Default fallback
        return self._noncritical(entry, "unclassified drift")

    # -------------------------
    # Internal helpers
    # -------------------------

    def _matches(self, path: str, patterns: list[str]) -> bool:
        return any(p in path.lower() for p in patterns)

    def _override(self, entry: DriftEntry) -> Dict[str, Any]:
        return {
            "type": entry.reason,
            "reason": "explicit override",
            "backend": entry.backend,
            "path": entry.path,
            "expected": entry.expected,
            "actual": entry.actual,
        }

    def _critical(self, entry: DriftEntry, reason: str) -> Dict[str, Any]:
        return {
            "type": "critical",
            "reason": reason,
            "backend": entry.backend,
            "path": entry.path,
            "expected": entry.expected,
            "actual": entry.actual,
        }

    def _noncritical(self, entry: DriftEntry, reason: str) -> Dict[str, Any]:
        return {
            "type": "noncritical",
            "reason": reason,
            "backend": entry.backend,
            "path": entry.path,
            "expected": entry.expected,
            "actual": entry.actual,
        }

    def _benign(self, entry: DriftEntry, reason: str) -> Dict[str, Any]:
        return {
            "type": "benign",
            "reason": reason,
            "backend": entry.backend,
            "path": entry.path,
            "expected": entry.expected,
            "actual": entry.actual,
        }
        