# Changelog

## [0.2.0] - 2025-12-24
### Added
- Standardized file headers with Created/Modified dates and file path.
- Vault integration for `sudo_password` resolution.
- Modular `main.py` orchestrating loader pipeline.
- Update script to refresh `Modified:` headers across package files.

### Changed
- Rewrote BotScanner entry point for audit clarity and maintainability.
- Updated `pyproject.toml` to version 0.2.0 with aligned dependencies.
- Requires Python >=3.12 for runtime.
- Dependencies aligned with pinned `requirements.txt` for reproducibility.

### Removed
- Legacy `main.py` archived with datestamp.