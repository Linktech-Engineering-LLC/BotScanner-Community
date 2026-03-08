"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-13
Modified: 2026-02-13
File: tests/firewall/activation/test_activation_map_builder.py
Description: Describe the purpose of this file
"""

# System Libraries
import pytest
# Project Libraries
from BotScanner.loggers import LoggerFactory
from BotScanner.firewall.canonical.builder import CanonicalBuilder
from BotScanner.firewall.enforcers.builder import ActivationMapBuilder
from BotScanner.firewall.enforcers.error_classes import ConfigError
from BotScanner.firewall.rule import Rule

lgr_cfg = {
    "path": "/tmp/test_activation_map.log",
    "level": "DEBUG",
}

lgr_fctry = LoggerFactory(lgr_cfg,"test_activation_map_builder")
logger = lgr_fctry.get()
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_builder(backend_registry=None, cfg=None):
    backend_registry = backend_registry or {
        "inet": {
            "chains": {"INPUT": {}, "FORWARD": {}},
            "sets": {"trusted": {}, "public": {}},
        }
    }

    cfg = cfg or {
        "firewall": {
            "rules": [],
            "ifaces": {},
        },
        "runtime": {
            "live_interfaces": {},
            "iface_info": {},
            "bridges": {},
        },
    }

    return ActivationMapBuilder(cfg=cfg, backend_registry=backend_registry)


# ---------------------------------------------------------------------------
# normalize_rule_activation
# ---------------------------------------------------------------------------

def test_normalize_rule_activation_basic():
    cfg = {
        "firewall": {
            "rules": [
                {
                    "chain": "INPUT",
                    "proto": "tcp",
                    "dport": 22,
                }
            ],
            "ifaces": {},
        },
        "runtime": {
            "live_interfaces": {},
            "iface_info": {},
            "bridges": {},
        },
    }

    # FIX: ActivationMapBuilder requires (cfg, lgr_cfg)
    builder = ActivationMapBuilder(cfg, lgr_cfg)

    activation_map = builder.build()

    assert 0 in activation_map["rules"]
    r = activation_map["rules"][0]

    assert r["chain"] == "INPUT"
    assert r["proto"] == "tcp"
    assert r["dport"] == 22

    assert r["action"] == "accept"
    assert r["order"] == 0
    assert r["declared"] is True
    assert r["active"] is True
    assert r["required"] is True
    
def test_validate_rule_dependencies_missing_chain():
    cfg = {
        "firewall": {
            "rules": [
                {
                    # missing chain
                    "proto": "tcp",
                    "dport": 22,
                }
            ],
            "ifaces": {},
        },
        "runtime": {
            "live_interfaces": {},
            "iface_info": {},
            "bridges": {},
        },
    }

    # FIX: ActivationMapBuilder requires (cfg, lgr_cfg)
    builder = ActivationMapBuilder(cfg, lgr_cfg)

    # Build activation map
    activation_map = builder.build()

    # Now validate dependencies — this is where missing chain is caught in v3
    with pytest.raises(ConfigError):
        builder.validate_rule_dependencies(
            activation_map["rules"][0],
            activation_map
        )

def test_invalid_port_type_in_canonical_builder():
    cfg = {
        "firewall": {
            "rules": [
                {
                    "chain": "INPUT",
                    "dport": "not-an-int",   # invalid
                }
            ],
            "ifaces": {},
        },
        "runtime": {
            "live_interfaces": {},
            "iface_info": {},
            "bridges": {},
        },
    }

    # Build activation map (this will NOT raise)
    activation = ActivationMapBuilder(cfg, lgr_cfg).build()

    # Build element map (empty for this test)
    elements = {
        "sets": {},
        "chains": {},
    }

    # CanonicalBuilder is where invalid port types are caught
    with pytest.raises(ConfigError):
        CanonicalBuilder(cfg, activation, elements).build()
        
def test_validate_rule_dependencies_valid():
    # v3: no backend_registry, no Rule objects
    builder = ActivationMapBuilder(cfg={
        "firewall": {"rules": [], "ifaces": {}},
        "runtime": {"live_interfaces": {}, "iface_info": {}, "bridges": {}},
    }, lgr_cfg=lgr_cfg)

    activation_map = {
        "sets": {
            "trusted": {"required": False},
        },
        "chains": {
            "INPUT": {"required": False},
        },
        "rules": {
            0: {}  # placeholder, not used by this test
        },
    }

    rule_data = {
        "chain": "INPUT",
        "src_zone": "trusted",
        "proto": "tcp",
        "dport": 22,
    }

    # v3: validate_rule_dependencies takes (rule_data, activation_map)
    builder.validate_rule_dependencies(rule_data, activation_map)

    assert activation_map["chains"]["INPUT"]["required"] is True
    assert activation_map["sets"]["trusted"]["required"] is True

def test_validate_rule_dependencies_missing_chain():
    # v3: no backend_registry, no Rule objects
    builder = ActivationMapBuilder(cfg={
        "firewall": {"rules": [], "ifaces": {}},
        "runtime": {"live_interfaces": {}, "iface_info": {}, "bridges": {}},
    }, lgr_cfg=lgr_cfg)

    activation_map = {
        "sets": {},
        "chains": {},
        "rules": {
            0: {}  # placeholder, not used by this test
        },
    }

    rule_data = {"chain": "MISSING"}

    # v3: validate_rule_dependencies takes (rule_data, activation_map)
    with pytest.raises(ConfigError):
        builder.validate_rule_dependencies(rule_data, activation_map)

def test_validate_rule_dependencies_missing_zone():
    # v3: no backend_registry, no Rule objects
    builder = ActivationMapBuilder(cfg={
        "firewall": {"rules": [], "ifaces": {}},
        "runtime": {"live_interfaces": {}, "iface_info": {}, "bridges": {}},
    }, lgr_cfg=lgr_cfg)

    activation_map = {
        "sets": {},
        "chains": {"INPUT": {"required": False}},
        "rules": {
            0: {}  # placeholder, not used by this test
        },
    }

    rule_data = {
        "chain": "INPUT",
        "src_zone": "unknown_zone",
    }

    # v3: validate_rule_dependencies takes (rule_data, activation_map)
    with pytest.raises(ConfigError):
        builder.validate_rule_dependencies(rule_data, activation_map)

def test_validate_rule_dependencies_direct_set_reference():
    # v3: no backend_registry, no Rule objects
    builder = ActivationMapBuilder(cfg={
        "firewall": {"rules": [], "ifaces": {}},
        "runtime": {"live_interfaces": {}, "iface_info": {}, "bridges": {}},
    }, lgr_cfg=lgr_cfg)

    activation_map = {
        "sets": {"trusted": {"required": False}},
        "chains": {"INPUT": {"required": False}},
        "rules": {0: {}},  # placeholder, not used by this test
    }

    rule_data = {
        "chain": "INPUT",
        "set_name": "trusted",
    }

    # v3: validate_rule_dependencies takes (rule_data, activation_map)
    builder.validate_rule_dependencies(rule_data, activation_map)

    assert activation_map["sets"]["trusted"]["required"] is True
