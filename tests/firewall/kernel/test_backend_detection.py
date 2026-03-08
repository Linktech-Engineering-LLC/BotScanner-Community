"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-01
Modified: 2026-02-02
File: BotScanner/tests/firewall/kernel/test_backend_detection.py
Description: Describe the purpose of this file
"""
# System Libraries
import pytest
from unittest.mock import patch
# Project Libraries
from BotScanner.firewall.enforcers.helpers.detect import (
    detect_kernel_backend,
    detect_manager_backend,
    select_backends,
    KernelBackend,
    ManagerBackend,
)

# Simple mock result object for sudo_run
class MockResult:
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg


# ------------------------------------------------------------
# Kernel backend detection tests
# ------------------------------------------------------------

def test_kernel_detects_nftables_ruleset():
    # nft list ruleset succeeds
    with patch("BotScanner.firewall.enforcers.helpers.detect.sudo_run") as mock_run:
        mock_run.return_value = MockResult(0, "table inet filter")
        result = detect_kernel_backend("pw")
        assert result == KernelBackend.NFTABLES


def test_kernel_detects_firewalld_implies_nftables():
    # nft fails, firewalld active
    with patch("BotScanner.firewall.enforcers.helpers.detect.sudo_run") as mock_run:
        mock_run.side_effect = [
            MockResult(1, ""),          # nft list ruleset
            MockResult(0, "active"),    # firewalld
        ]
        result = detect_kernel_backend("pw")
        assert result == KernelBackend.NFTABLES


def test_kernel_detects_iptables_nft_shim():
    # nft fails, firewalld inactive, iptables-nft shim
    with patch("BotScanner.firewall.enforcers.helpers.detect.sudo_run") as mock_run:
        mock_run.side_effect = [
            MockResult(1, ""),                         # nft
            MockResult(3, "inactive"),                 # firewalld
            MockResult(0, "iptables v1.8.7 (nf_tables)")  # iptables
        ]
        result = detect_kernel_backend("pw")
        assert result == KernelBackend.NFTABLES


def test_kernel_detects_iptables_legacy():
    # nft fails, firewalld inactive, iptables-legacy
    with patch("BotScanner.firewall.enforcers.helpers.detect.sudo_run") as mock_run:
        mock_run.side_effect = [
            MockResult(1, ""),                         # nft
            MockResult(3, "inactive"),                 # firewalld
            MockResult(0, "iptables v1.8.7 (legacy)")  # iptables
        ]
        result = detect_kernel_backend("pw")
        assert result == KernelBackend.IPTABLES


def test_kernel_detects_unknown():
    # nft fails, firewalld inactive, iptables fails
    with patch("BotScanner.firewall.enforcers.helpers.detect.sudo_run") as mock_run:
        mock_run.side_effect = [
            MockResult(1, ""),   # nft
            MockResult(3, ""),   # firewalld
            MockResult(1, ""),   # iptables
        ]
        result = detect_kernel_backend("pw")
        assert result == KernelBackend.UNKNOWN


# ------------------------------------------------------------
# Manager backend detection tests
# ------------------------------------------------------------

def test_manager_detects_firewalld():
    with patch("BotScanner.firewall.enforcers.helpers.detect.sudo_run") as mock_run:
        mock_run.side_effect = [
            MockResult(0, "active"),  # firewalld
        ]
        result = detect_manager_backend("pw")
        assert result == ManagerBackend.FIREWALLD


def test_manager_detects_ufw():
    with patch("BotScanner.firewall.enforcers.helpers.detect.sudo_run") as mock_run:
        mock_run.side_effect = [
            MockResult(3, "inactive"),     # firewalld
            MockResult(0, "Status: active")  # ufw
        ]
        result = detect_manager_backend("pw")
        assert result == ManagerBackend.UFW


def test_manager_detects_none():
    with patch("BotScanner.firewall.enforcers.helpers.detect.sudo_run") as mock_run:
        mock_run.side_effect = [
            MockResult(3, ""),  # firewalld
            MockResult(1, ""),  # ufw
        ]
        result = detect_manager_backend("pw")
        assert result == ManagerBackend.NONE


# ------------------------------------------------------------
# select_backends() reconciliation tests
# ------------------------------------------------------------

def test_select_firewalld_forces_nftables():
    with patch("BotScanner.firewall.enforcers.helpers.detect.detect_kernel_backend") as k, \
         patch("BotScanner.firewall.enforcers.helpers.detect.detect_manager_backend") as m:

        k.return_value = KernelBackend.IPTABLES
        m.return_value = ManagerBackend.FIREWALLD

        result = select_backends("pw")
        assert result.kernel == KernelBackend.NFTABLES
        assert result.manager == ManagerBackend.FIREWALLD


def test_select_ufw_does_not_override_kernel():
    with patch("BotScanner.firewall.enforcers.helpers.detect.detect_kernel_backend") as k, \
         patch("BotScanner.firewall.enforcers.helpers.detect.detect_manager_backend") as m:

        k.return_value = KernelBackend.IPTABLES
        m.return_value = ManagerBackend.UFW

        result = select_backends("pw")
        assert result.kernel == KernelBackend.IPTABLES
        assert result.manager == ManagerBackend.UFW


def test_select_none_does_not_override_kernel():
    with patch("BotScanner.firewall.enforcers.helpers.detect.detect_kernel_backend") as k, \
         patch("BotScanner.firewall.enforcers.helpers.detect.detect_manager_backend") as m:

        k.return_value = KernelBackend.UNKNOWN
        m.return_value = ManagerBackend.NONE

        result = select_backends("pw")
        assert result.kernel == KernelBackend.UNKNOWN
        assert result.manager == ManagerBackend.NONE
