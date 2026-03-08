"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-09
Modified: 2026-02-09
File: BotScanner/firewall/backend.py
Description:
    Backend translators for nftables, firewalld, and iptables.
    These classes convert canonical Rule objects into backend-specific
    commands or rule expressions for enforcement.
"""
# System Libraries
from typing import List
from .rule import Rule
# Project Libraries
from .backend.nftables import NftablesBackend
from .backend.firewalld import FirewalldBackend
from .backend.ufw_backend import UfwBackend


# ---------------------------------------------------------------------------
# Backend Factory
# ---------------------------------------------------------------------------

def get_backend(name: str, cfg: dict, lgr_cfg: dict) -> Backend:
    name = name.lower()

    if name == "nftables":
        return NftablesBackend(cfg, lgr_cfg)

    if name == "firewalld":
        return FirewalldBackend(cfg, lgr_cfg)

    if name == "ufw":
        return UfwBackend(cfg, lgr_cfg)

    raise ValueError(f"Unknown backend: {name}")