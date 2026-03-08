"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-17
Modified: 2026-01-17
File: BotScanner/firewall/backend/helpers/canonical_utils.py
Description: Describe the purpose of this file
"""
# System Libraries
# Project Libraries


def canonical_json_safe(obj):
    if isinstance(obj, dict):
        return {k: canonical_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [canonical_json_safe(v) for v in obj]
    if isinstance(obj, set):
        return sorted(canonical_json_safe(v) for v in obj)
    return obj