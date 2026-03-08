"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-01
Modified: 2026-02-05
File: BotScanner/firewall/baseline.py
Description: Baseline and drift storage utilities for firewall backends (v2).
"""
# System Libraries
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
# Project Libraries
from .rule import Rule
from ..utils.common import current_timestamp

class BaseLine:
    """
    v2 Baseline/drift storage.

    Responsibilities:
      - Resolve canonical paths for baseline/drift/cross-drift/nft files
      - Load and save JSON baselines/drift/cross-drift
      - Enforce that only 'nftables' may produce .nft baseline files
    """

    VALID_TYPES = {"backend", "drift", "cross-drift", "nft"}

    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        factory = lgr_cfg.get("factory")
        self.logger = factory.get_logger("baseline") if factory else None

    # ----------------------------------------------------------------------
    # Path resolution
    # ----------------------------------------------------------------------
    @staticmethod
    def _data_dir(cfg: dict) -> Path:
        paths_cfg = cfg.get("paths", {})
        data_dir = paths_cfg.get("data_dir")
        if not data_dir:
            raise ValueError("data_dir is not configured in cfg['paths']['data_dir']")
        return Path(data_dir)

    @classmethod
    def baseline_path(
        cls,
        cfg: dict,
        owner: str,
        backend: Optional[str],
        file_type: str,
        ext: Optional[str] = None,
        logger=None,
    ) -> Optional[Path]:
        """
        Canonical path for baseline/drift/cross-drift/nft files.

        Naming:
            {backend}-{file_type}.{ext}

        Special cases:
            - cross-drift: backend is ignored, filename = cross-drift.{ext}
            - nft: only 'nftables' backend allowed, filename = nftables-nft.nft
        """

        if file_type not in cls.VALID_TYPES:
            raise ValueError(f"Invalid file_type '{file_type}', must be one of {cls.VALID_TYPES}")

        data_dir = cls._data_dir(cfg)
        owner_dir = data_dir / owner
        owner_dir.mkdir(parents=True, exist_ok=True)

        # nft: only nftables backend, forced .nft extension
        if file_type == "nft":
            if backend != "nftables":
                if logger:
                    logger.error(
                        f"[BASELINE] Backend '{backend}' attempted to request an nft baseline "
                        f"but only 'nftables' may produce .nft files"
                    )
                return None

            ext = "nft"
            filename = f"{backend}-nft.{ext}"
            path = owner_dir / filename

            if logger:
                logger.debug(
                    f"[BASELINE] owner={owner} backend={backend} file_type={file_type} path={path}"
                )
            return path

        # Default extension for non-nft types
        ext = ext or "json"

        # cross-drift: no backend in filename
        if file_type == "cross-drift":
            filename = f"{file_type}.{ext}"
        else:
            if not backend:
                raise ValueError(f"backend is required for file_type '{file_type}'")
            filename = f"{backend}-{file_type}.{ext}"

        path = owner_dir / filename

        if logger:
            logger.debug(
                f"[BASELINE] owner={owner or 'global'} backend={backend} file_type={file_type} path={path}"
            )

        return path

    # ----------------------------------------------------------------------
    # Static File I/O methods
    # ----------------------------------------------------------------------
    @staticmethod
    def _load_json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def sanitize_baseline(baseline: dict) -> dict:
        sanitized = {}
        for key, value in baseline.items():
            if key == "nft_raw":
                continue
            if isinstance(value, str) and "\n" in value:
                sanitized[key] = value.splitlines()
            else:
                sanitized[key] = value
        return sanitized

    @staticmethod
    def _save_json(path: Path, data: dict):
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def _save_txt(backend_name: str, baseline: dict, path: Path) -> None:
        """Save baseline as TXT with header + datestamp."""
        header = (
            f"# Baseline snapshot for {backend_name}\n"
            f"# Written: {current_timestamp()}\n\n"
        )
        body = json.dumps(baseline, indent=2)
        path.write_text(f"{header}{body}", encoding="utf-8")

    @staticmethod
    def _compute_checksum(json_path: Path) -> str:
        """Compute SHA256 checksum of a JSON file."""
        h = hashlib.sha256()
        with json_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _compute_model_hash(self, canonical_rules: list[dict]) -> str:
        """
        Compute a deterministic SHA256 hash of the canonical baseline model.
        This is used to detect whether the baseline is outdated relative to
        the current normalized rules.
        """
        payload = {"rules": canonical_rules}

        # Deterministic JSON: sorted keys, compact separators
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @staticmethod
    def _save_checksum(json_path: Path) -> Path:
        """Save SHA256 checksum of JSON baseline to a sidecar file."""
        digest = BaseLine._compute_checksum(json_path)
        checksum_path = json_path.with_suffix(".sha256")
        checksum_path.write_text(
            f"# Baseline checksum\n"
            f"# Written: {datetime.now().isoformat(timespec='seconds')}\n"
            f"# File: {json_path.name}\n"
            f"SHA256={digest}\n",
            encoding="utf-8"
        )
        return checksum_path

    @staticmethod
    def _verify_checksum(json_path: Path) -> bool:
        """Validate JSON file against its .sha256 sidecar."""
        checksum_path = json_path.with_suffix(".sha256")
        if not checksum_path.exists():
            return False

        # Read all lines and find the SHA256= line
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
        digest_line = next((l for l in lines if l.startswith("SHA256=")), None)
        if not digest_line:
            return False

        expected = digest_line.split("=", 1)[1].strip()
        actual = BaseLine._compute_checksum(json_path)

        return expected == actual

    def is_current(self, owner: str, backend: str) -> bool:
        """
        Determine whether the backend baseline for (owner, backend) is current.

        A baseline is considered CURRENT only if:
        - JSON baseline exists
        - metadata sidecar exists
        - metadata.version matches expected version
        - metadata.model_hash matches the hash of the current normalized model
        - metadata.last_enforced >= JSON baseline mtime

        Otherwise, the baseline is OUTDATED and drift detection must be skipped.
        """

        # ------------------------------------------------------------
        # 1. Resolve baseline paths
        # ------------------------------------------------------------
        json_path = self.baseline_path(
            cfg=self.cfg,
            owner=owner,
            backend=backend,
            file_type="backend",
            ext="json",
            logger=self.logger,
        )

        if json_path is None or not json_path.exists():
            if self.logger:
                self.logger.debug(f"[BASELINE] No JSON baseline for {owner}/{backend}")
            return False

        meta_path = json_path.with_suffix(".meta.json")
        if not meta_path.exists():
            if self.logger:
                self.logger.debug(f"[BASELINE] No metadata for {owner}/{backend}")
            return False

        # ------------------------------------------------------------
        # 2. Load metadata
        # ------------------------------------------------------------
        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as e:
            if self.logger:
                self.logger.warning(f"[BASELINE] Invalid metadata for {owner}/{backend}: {e}")
            return False

        # ------------------------------------------------------------
        # 3. Validate metadata version
        # ------------------------------------------------------------
        if metadata.get("version") != 1:
            if self.logger:
                self.logger.debug(
                    f"[BASELINE] Metadata version mismatch for {owner}/{backend}: "
                    f"{metadata.get('version')} != 1"
                )
            return False

        # ------------------------------------------------------------
        # 4. Validate model hash
        # ------------------------------------------------------------
        # Load current canonical model (rules) for comparison
        current_rules = self._load_current_canonical_rules(owner, backend)
        if current_rules is None:
            if self.logger:
                self.logger.debug(
                    f"[BASELINE] Cannot load current canonical rules for {owner}/{backend}"
                )
            return False

        current_hash = self._compute_model_hash(current_rules)
        if metadata.get("model_hash") != current_hash:
            if self.logger:
                self.logger.debug(
                    f"[BASELINE] Model hash mismatch for {owner}/{backend}: "
                    f"{metadata.get('model_hash')} != {current_hash}"
                )
            return False

        # ------------------------------------------------------------
        # 5. Validate timestamp (baseline must not be older than last_enforced)
        # ------------------------------------------------------------
        try:
            last_enforced = datetime.fromisoformat(metadata["last_enforced"].replace("Z", "+00:00"))
        except Exception:
            if self.logger:
                self.logger.debug(f"[BASELINE] Invalid last_enforced timestamp for {owner}/{backend}")
            return False

        baseline_mtime = datetime.utcfromtimestamp(json_path.stat().st_mtime)

        if baseline_mtime < last_enforced:
            if self.logger:
                self.logger.debug(
                    f"[BASELINE] Baseline outdated for {owner}/{backend}: "
                    f"mtime={baseline_mtime}, last_enforced={last_enforced}"
                )
            return False

        # ------------------------------------------------------------
        # If all checks passed, baseline is current
        # ------------------------------------------------------------
        return True

    def _load_current_canonical_rules(self, owner: str, backend: str) -> list[dict] | None:
        """
        Return the canonical rule dicts for hashing, matching the structure
        used in save_backend_baseline().
        """
        if not hasattr(self, "_current_models"):
            return None

        rules = self._current_models.get((owner, backend))
        if not rules:
            return None

        # Attach rule_id, sort, and convert to dicts
        rules_with_ids = [r.with_rule_id() for r in rules]
        rules_sorted = sorted(rules_with_ids, key=lambda r: r.sort_key())
        return [r.to_dict() for r in rules_sorted]

    def set_current_canonical_rules(self, owner: str, backend: str, rules: list[Rule]) -> None:
        """
        Store the current canonical Rule objects for (owner, backend).
        These are later used by is_current() to compute the model_hash
        and determine whether the baseline is outdated.

        The enforcer/backend must call this BEFORE drift detection.
        """
        if not hasattr(self, "_current_models"):
            self._current_models = {}

        # Store the raw Rule objects; canonicalization happens in _load_current_canonical_rules
        self._current_models[(owner, backend)] = rules

    # ----------------------------------------------------------------------
    # Public API: backend baseline
    # ----------------------------------------------------------------------
    def load_backend_baseline(self, owner: str, backend: str) -> dict:
        """
        Load backend baseline JSON, validating against its checksum sidecar.
        Returns {} if missing, corrupted, or checksum mismatch.
        """
        json_path = self.baseline_path(
            cfg=self.cfg,
            owner=owner,
            backend=backend,
            file_type="backend",
            ext="json",
            logger=self.logger,
        )

        if not json_path or not json_path.exists():
            self.logger.warning(f"[BASELINE] No baseline JSON for backend={backend}")
            return None

        # Validate checksum before loading
        if not BaseLine._verify_checksum(json_path):
            self.logger.error(f"[BASELINE] Checksum validation failed for {json_path}")
            return {}

        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            rules = data.get("rules", [])
            return [Rule.from_dict(r) for r in rules]
        except json.JSONDecodeError as e:
            self.logger.error(f"[BASELINE] Corrupted JSON in {json_path}: {e}")
            return {}
        
    def save_backend_baseline(self, owner: str, backend: str, rules: list[Rule]) -> dict[str, Path]:
        """
        Save canonical backend baseline JSON and TXT for a given owner/backend.
        Returns (json_path, txt_path).
        """

        json_path = self.baseline_path(
            cfg=self.cfg,
            owner=owner,
            backend=backend,
            file_type="backend",
            ext="json",
            logger=self.logger,
        )
        txt_path = self.baseline_path(
            cfg=self.cfg,
            owner=owner,
            backend=backend,
            file_type="backend",
            ext="txt",
            logger=self.logger,
        )

        if json_path is None or txt_path is None:
            raise RuntimeError(
                f"[BASELINE] Cannot save backend baseline for owner={owner} backend={backend}"
            )

        # 1. Attach rule_id to each rule
        rules_with_ids = [r.with_rule_id() for r in rules]

        # 2. Sort using semantic ordering
        rules_sorted = sorted(rules_with_ids, key=lambda r: r.sort_key())

        # 3. Convert to canonical dicts
        canonical = [r.to_dict() for r in rules_sorted]

        # 4. Save JSON baseline
        self._save_json(json_path, {"rules": canonical})

        # 5. Save checksum
        checksum_path = self._save_checksum(json_path)

        # 6. Save TXT baseline (header + timestamp)
        # TXT should show only metadata, not rule content
        self._save_txt(backend, {"count": len(canonical)}, txt_path)

        paths = {
            "json": json_path,
            "txt": txt_path,
            "checksum": checksum_path,
        }

        # 7. Save metadata sidecar
        meta_path = json_path.with_suffix(".meta.json")
        metadata = {
            "version": 1,
            "last_enforced": datetime.utcnow().isoformat() + "Z",
            "model_hash": self._compute_model_hash(canonical),
        }
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        paths = {
            "json": json_path,
            "txt": txt_path,
            "checksum": checksum_path,
            "meta": meta_path,
        }

        if self.logger:
            for key, path in paths.items():
                self.logger.info(f"[BASELINE] saved {key} baseline to {str(path)}")

        return paths

    # ----------------------------------------------------------------------
    # Public API: nft baseline path only (content handled elsewhere)
    # ----------------------------------------------------------------------
    def get_nft_baseline_path(self, owner: str, backend: str) -> Optional[Path]:
        """
        Return the path for an nft baseline file for a given owner/backend.
        Only 'nftables' backend is allowed; returns None otherwise.
        """
        path = self.baseline_path(
            cfg=self.cfg,
            owner=owner,
            backend=backend,
            file_type="nft",
            logger=self.logger,
        )
        if path is None and self.logger:
            self.logger.info(
                f"[BASELINE] nft baseline path not available for owner={owner} backend={backend}"
            )
        return path

