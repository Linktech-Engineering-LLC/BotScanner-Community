"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-24
Modified: 2026-01-24
File: BotScanner/firewall/semantic_model.py
Description: Describe the purpose of this file
"""
# System Imports
# Project Imports

SEMANTIC_MODEL = {
    "zones": dict,
    "services": dict,
    "ports": dict,
    "protocols": dict,
    "nat": dict,
    "forwarding": dict,
    "rules": list,
}

def empty_semantic():
    return {
        "zones": {},
        "services": {},
        "ports": {},
        "protocols": {},
        "nat": {},
        "forwarding": {},
        "rules": [],
    }