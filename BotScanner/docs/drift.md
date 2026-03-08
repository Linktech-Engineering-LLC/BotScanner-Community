# Drift Detection Documentation

This document describes how BotScanner handles baseline, drift, and cross-drift.

---

## Baseline
- **Purpose**: Canonical snapshot of backend state.
- **Artifacts**: Stored in normalized format for audit clarity.
- **Validation**: Baseline must exist and be valid before drift detection runs.

## Drift
- **Definition**: Comparison between current backend state and recorded baseline.
- **Artifacts**: Drift files show differences line-by-line.
- **Normalization**: Both baseline and current captures normalized before comparison.
- **Lifecycle Logging**: Explicit start banners, empty drift handling, fallback events.

## Cross-Drift
- **Definition**: Comparison between two current backends (e.g. manager vs kernel).
- **Artifacts**: Normalized files with headers (`owner: global`, `backend: cross`).
- **Purpose**: Detect inconsistencies between active backends, independent of baseline.

---

## Notes
- Drift pipeline ensures audit transparency.
- Cross-drift complements baseline drift by checking live backend consistency.
- Artifacts are append-only, with deterministic naming for reproducibility.