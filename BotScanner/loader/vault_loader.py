"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-24
Modified: 2026-03-12
File: BotScanner/loader/vault_loader.py
Description: VaultLoader loads vault.yml and provides safe access to secrets such as
             sudo_passwords and API tokens, without merging them into host objects.
"""
# Standard library imports
import os
from pathlib import Path
import yaml
from ansible.parsing.vault import VaultLib, VaultSecret

class VaultLoader:
    def __init__(self, cfg_vault: dict, password_candidate: str | None = None):
        self.cfg_vault = cfg_vault  # <-- store config dict
        # Resolve vault and password paths
        self.vault_file, self.password_file = self._resolve_paths(cfg_vault)
        self.password = self._get_vault_password(password_candidate)
        self.vault = VaultLib([(None, VaultSecret(self.password.encode()))])
        self.data = {}  # always initialize

    def _resolve_paths(self, cfg_vault: dict):
        """Resolve vault and password file paths based on config and env variables."""
        if cfg_vault.get("use_env_variable", True):
            vault_path = Path(os.getenv(cfg_vault.get("vault_env_variable", ""), None)).expanduser()
            pass_path = Path(os.getenv(cfg_vault.get("password_env_variable", ""), None)).expanduser()
        else:
            vault_path = None
            pass_path = None

        # Fall back to configured defaults if env not set
        vault_path = vault_path or str(Path(cfg_vault.get("vault_path")).expanduser())
        pass_path = pass_path or str(Path(cfg_vault.get("password_file")).expanduser())

        return Path(vault_path), Path(pass_path)

    def _get_vault_password(self, candidate: str | None = None) -> str:
        """Retrieve vault password from env, CLI candidate, or prompt."""
        # 1. Password file from resolved path
        if self.password_file.exists():
            return self.password_file.read_text(encoding="utf-8").strip()

        # 2. CLI candidate
        if candidate:
            path_candidate = Path(candidate).expanduser()
            if path_candidate.exists() and path_candidate.is_file():
                return path_candidate.read_text(encoding="utf-8").strip()
            return candidate  # treat as literal string

        # 3. Fallback prompt
        return input("Vault password: ").strip()

    def load(self):
        """Load and decrypt vault.yml into a dict."""
        if not self.vault_file.exists():
            raise FileNotFoundError(f"Vault file not found: {self.vault_file}")

        with open(self.vault_file, "r", encoding="utf-8") as f:
            raw = f.read()

        # Decrypt vault.yml content
        decrypted = self.vault.decrypt(raw)
        # If decrypt() returns bytes, decode to str
        if isinstance(decrypted, bytes):
            decrypted = decrypted.decode("utf-8")
        # If it looks like a quoted string with \n, unescape it
        if "\\n" in decrypted:
            decrypted = decrypted.encode("utf-8").decode("unicode_escape")

        parsed = yaml.safe_load(decrypted)

        if not isinstance(parsed, dict):
            raise ValueError("vault.yml must contain a dictionary at the top level")
        self.data = parsed

        # Filter by key if specified
        key = self.cfg_vault.get("key")
        if key:
            if key not in parsed:
                raise KeyError(f"Vault key '{key}' not found in vault.yml")
            self.data = parsed[key]
        else:
            self.data = parsed

        return self.data
        
    def has(self, key: str, *args) -> bool:
        """Check if a key exists in the vault data."""
        if not self.data:
            self.load()
        return key in self.data

    def get(self, key, default=None):
        if not self.data:
            self.load()
        value = self.data.get(key, default)
        return value

    def __getitem__(self, key):
        if not self.data:
            self.load()
        return self.data[key]

    def __contains__(self, key):
        if not self.data:
            self.load()
        return key in self.data

