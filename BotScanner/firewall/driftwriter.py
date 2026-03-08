"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-03
Modified: 2026-01-28
File: BotScanner/firewall/driftwriter.py
Description: Describe the purpose of this file
"""
# System Libraries
import json
from pathlib import Path
from datetime import datetime, timedelta
# Project Libraries
from .baseline import BaseLine
from .backend.helpers.canonical_utils import canonical_json_safe

class DriftWriter:
    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.logger = lgr_cfg["factory"].get_logger("driftwriter")

    def write_drift(self, owner: str, backend: str, drift: dict) -> Path:
        """
        Write drift results to disk.

        `drift` is expected to be the *classified* drift structure:
        {
            "critical": [...],
            "noncritical": [...],
            "benign": [...]
        }
        """

        # Select config block
        if backend == "cross":
            drift_cfg = self.cfg.get("cross_drift", {})
            file_type = "cross-drift"
            owner = "global"
        else:
            drift_cfg = self.cfg.get("drift", {})
            file_type = "drift"

        datestamp = drift_cfg.get("datestamp", False)
        rotate = drift_cfg.get("rotate", False)
        rotation_cfg = drift_cfg.get("rotation", {}) or {}
        link = rotation_cfg.get("link", True)

        path = BaseLine.baseline_path(
            self.cfg,
            owner=owner,
            backend=backend,
            file_type=file_type,
            ext="json",
            logger=self.logger,
        )

        if path is None:
            self.logger.error(f"[DRIFT] Cannot write drift for backend='{backend}' owner='{owner}'")
            return

        # Apply datestamp if enabled
        if datestamp:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            stem = path.stem
            path = path.with_name(f"{stem}-{stamp}{path.suffix}")

        # Build header
        header = {
            "generated": datetime.now().isoformat(timespec="seconds"),
            "owner": owner,
            "backend": backend,
            "version": "3.0",
            "previous_drift": str(self._get_previous_symlink(path, backend))
        }

        # Final artifact
        artifact = {
            "header": header,
            "drift": drift,
            "text_diff": drift.get("text_diff", ""),
            "summary": drift.get("summary", [])
        }

        safe_artifact = canonical_json_safe(artifact)

        # Write JSON
        path.write_text(json.dumps(safe_artifact, indent=2), encoding="utf-8")

        # Update symlink and cleanup
        if link:
            self._update_symlink(path, backend)
        if rotate:
            self._rotate_drifts(path, backend, rotation_cfg)

        self.logger.info(f"[DRIFT] Drift written to {path}")
        return path

    # Rotation cleanup (max_count / max_age_days) would go here
    def _rotate_drifts(self, json_path: Path, backend: str, rotate_cfg: dict):
        """
        Apply rotation policy to drift files in drift_dir.
        Handles both backend drift and cross-drift.
        """
        drift_dir = json_path.parent
        max_count = rotate_cfg.get("max_count", 0)
        max_age_days = rotate_cfg.get("max_age_days", 0)

        # Determine prefix for file matching
        if backend == "cross":
            prefix = "cross-drift"
        else:
            prefix = f"{backend}-drift"

        valid_files = []
        for f in drift_dir.glob(f"{prefix}-*.json"):
            try:
                f.stat()  # ensure the file actually exists
                valid_files.append(f)
            except FileNotFoundError:
                self.logger.debug(f"[DRIFT] Skipping ghost file: {f}")
                continue

        drift_files = sorted(valid_files, key=lambda p: p.stat().st_mtime, reverse=True)

        # Enforce max_count
        if max_count > 0 and len(drift_files) > max_count:
            for old_file in drift_files[max_count:]:
                try:
                    old_file.unlink()
                    self.logger.debug(f"[ROTATE] Removed old drift file {old_file}")
                except Exception as e:
                    self.logger.warning(f"[ROTATE] Could not remove {old_file}: {e}")


        # Enforce max_age_days
        if max_age_days > 0:
            cutoff = datetime.now() - timedelta(days=max_age_days)
            for f in drift_files:
                if f.exists() and f.is_file():
                    mtime = datetime.fromtimestamp(f.stat().st_mtime)
                    if mtime < cutoff:
                        try:
                            f.unlink()
                            self.logger.debug(f"[ROTATE] Expired drift file {f}")
                        except Exception as e:
                            self.logger.warning(f"[ROTATE] Could not remove {f}: {e}")
                else:
                    self.logger.debug(f"[DRIFT] Skipping ghost or missing file: {f}")

    def safe_mtime(self, p: Path) -> float:
        try:
            return p.stat().st_mtime
        except FileNotFoundError:
            # Broken symlink or ghost entry
            self.logger.debug(f"[DRIFT] Skipping missing file during rotation: {p}")
            return 0.0  # or float('-inf') to push it to the front

    def _get_previous_symlink(self, new_file: Path, backend: str) -> Path | None:
        symlink = new_file.parent / ( "cross-latest.json" if backend == "cross"
                                    else f"{backend}-drift-latest.json" )
        if symlink.exists():
            try:
                return symlink.resolve()
            except FileNotFoundError:
                # Target was rotated/deleted
                self.logger.debug(f"[DRIFT] Previous symlink target missing for {backend}")
                return None
        return None


    def _update_symlink(self, new_file: Path, backend: str) -> Path:
        """
        Update symlink to point at the latest drift file.
        For cross-drift, symlink is 'cross-latest.json'.
        For backend drift, symlink is '<backend>-drift-latest.json'.
        """
        if backend == "cross":
            symlink = new_file.parent / "cross-latest.json"
        else:
            symlink = new_file.parent / f"{backend}-drift-latest.json"

        try:
            if symlink.exists() or symlink.is_symlink():
                symlink.unlink()
            symlink.symlink_to(new_file.name)
            self.logger.info(f"[DRIFT] Updated symlink: {symlink} -> {new_file.name}")
            return new_file
        except OSError as e:
            self.logger.error(f"[DRIFT] Failed to update symlink: {e}")
            return new_file
    

