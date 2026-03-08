"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-01
Modified: 2026-02-01
File: BotScanner/tests/firewall/kernel/test_enforcer_detection.py
Description: Describe the purpose of this file
"""
# System Libraries
import pytest
import pytest
from unittest.mock import patch, MagicMock

from BotScanner.firewall.orchestrator import FirewallOrchestrator
from BotScanner.firewall.enforcers.helpers.detect import KernelBackend

class DummyLogger:
    def debug(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass

class DummyLoggerFactory:
    def get_logger(self, *args, **kwargs):
        return DummyLogger()

dummy_lgr_cfg = {
    "factory": DummyLoggerFactory(),
    "active_flags": [],
    "flags_mask": "0x0"
}


@patch("BotScanner.firewall.orchestrator.select_backends")
@patch("BotScanner.firewall.orchestrator.ActivationMapBuilder")
@patch("BotScanner.firewall.orchestrator.NftablesEnforcer")
def test_enforcer_selection_nftables(mock_nft, mock_builder, mock_select):
    # Fake backend selection
    mock_select.return_value.kernel = KernelBackend.NFTABLES

    # Fake activation map
    mock_builder.return_value.build.return_value = {}

    orch = FirewallOrchestrator(cfg={}, lgr_cfg=dummy_lgr_cfg)

    orch._run_kernel_enforcement()

    mock_nft.assert_called_once()
    mock_nft.return_value.run.assert_called_once()
        
@patch("BotScanner.firewall.orchestrator.select_backends")
@patch("BotScanner.firewall.orchestrator.ActivationMapBuilder")
@patch("BotScanner.firewall.orchestrator.IptablesEnforcer")
def test_enforcer_selection_iptables(mock_ip, mock_builder, mock_select):
    mock_select.return_value.kernel = KernelBackend.IPTABLES
    mock_builder.return_value.build.return_value = {}

    orch = FirewallOrchestrator(cfg={}, lgr_cfg=dummy_lgr_cfg)

    orch._run_kernel_enforcement()

    mock_ip.assert_called_once()
    mock_ip.return_value.run.assert_called_once()
        
@patch("BotScanner.firewall.orchestrator.select_backends")
@patch("BotScanner.firewall.orchestrator.ActivationMapBuilder")
@patch("BotScanner.firewall.orchestrator.Ip6tablesEnforcer")
def test_enforcer_selection_ip6tables(mock_ip6, mock_builder, mock_select):
    mock_select.return_value.kernel = KernelBackend.IP6TABLES
    mock_builder.return_value.build.return_value = {}

    orch = FirewallOrchestrator(cfg={}, lgr_cfg=dummy_lgr_cfg)

    orch._run_kernel_enforcement()

    mock_ip6.assert_called_once()
    mock_ip6.return_value.run.assert_called_once()
        
@patch("BotScanner.firewall.orchestrator.select_backends")
@patch("BotScanner.firewall.orchestrator.NftablesEnforcer")
@patch("BotScanner.firewall.orchestrator.IptablesEnforcer")
@patch("BotScanner.firewall.orchestrator.Ip6tablesEnforcer")
def test_enforcer_selection_unknown_backend(mock_ip6, mock_ip, mock_nft, mock_select):
    # Simulate no backend detected
    mock_select.return_value.kernel = KernelBackend.UNKNOWN

    orch = FirewallOrchestrator(cfg={}, lgr_cfg=dummy_lgr_cfg)

    result = orch._run_kernel_enforcement()

    # Should return cleanly
    assert result is None

    # No enforcer should be instantiated
    mock_nft.assert_not_called()
    mock_ip.assert_not_called()
    mock_ip6.assert_not_called()