"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-18
Modified: 2026-02-11
File: BotScanner/firewall/enforcers/builder.py
Description: Responsible for constructing the activation map from:

- YAML interface definitions
- live interface enumeration
- bridge relationships
- IPv4/IPv6 address information

This module wraps helper routines, catches structured exceptions,
logs them with full context, and returns a structured result object
to the orchestrator or backend enforcer.

The Builder itself contains no backend logic and no YAML parsing.
"""
# System Libraries
from typing import Dict, Any, Tuple
# Project Libraries
from .helpers.helpers import ( 
    assign_yaml_interfaces_to_zones,
    validate_zone_interface_mapping, 
    detect_ip_families, 
)
from .error_classes import ( 
    ActivationMapError, 
    ZoneMappingError, 
    IPDetectionError, 
    BuilderFailure, 
    EmptyActivationMapError, 
    ConfigError,
)
from ..rule import Rule

class ActivationMapBuilder:
    """
    v3 Activation Map Builder
    -------------------------
    Phase 1: Zone activation (your existing logic)
    Phase 2: Set activation (new logic)
    Output: YAML-deterministic activation map for kernel enforcement
    """

    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        self.logger_factory = lgr_cfg.get("factory")
        self.logger = self.logger_factory.get_logger(module="activation_map")

    # ----------------------------------------------------------------------
    # PUBLIC ENTRYPOINT
    # ----------------------------------------------------------------------
    def build(self):
        self.logger.info("ActivationMapBuilder: starting build sequence")

        runtime = self.cfg.get("runtime", {})
        firewall_cfg = self.cfg.get("firewall", {})

        yaml_ifaces = firewall_cfg.get("ifaces", {})
        live_ifaces = runtime.get("live_interfaces", [])
        bridges = runtime.get("bridges", {})
        iface_info = runtime.get("iface_info", {})

        # Normalize live_ifaces into a dict keyed by interface name
        if isinstance(live_ifaces, dict):
            # Already correct shape
            pass

        elif isinstance(live_ifaces, list):
            # Case: list of strings
            if live_ifaces and isinstance(live_ifaces[0], str):
                live_ifaces = {
                    name: {
                        "name": name,
                        "altnames": [],
                        "ipv4": [],
                        "ipv6": [],
                    }
                    for name in live_ifaces
                }

            # Case: list of dicts
            elif live_ifaces and isinstance(live_ifaces[0], dict):
                live_ifaces = {iface["name"]: iface for iface in live_ifaces}

            else:
                live_ifaces = {}

        else:
            live_ifaces = {}
    
        # ------------------------------------------------------------
        # 1. Validate zone/interface mapping
        # ------------------------------------------------------------
        try:
            zone_map = validate_zone_interface_mapping(
                yaml_ifaces=yaml_ifaces,
                live_ifaces=live_ifaces,
                bridges=bridges,
                logger=self.logger,
            )
        except ZoneMappingError as e:
            self.logger.error(f"Zone/iface validation failed: {e}")
            return self._failure(e)

        # ------------------------------------------------------------
        # 2. Detect IPv4/IPv6 families
        # ------------------------------------------------------------
        try:
            enriched_zones = detect_ip_families(
                zone_map=zone_map,
                iface_info=iface_info,
                logger=self.logger,
            )
        except IPDetectionError as e:
            self.logger.error(f"IP detection failed: {e}")
            return self._failure(e)

        # ------------------------------------------------------------
        # 2a. IPv6 diagnostic logging
        # ------------------------------------------------------------
        for zone, data in enriched_zones.items():
            if not data["ipv6_enabled"]:
                had_ipv6 = any(
                    iface_info.get(iface, {}).get("ipv6")
                    for iface in data["interfaces"]
                )
                reason = "link-local-only" if had_ipv6 else "no-ipv6-addresses"
                self.logger.info(f"IPV6-DISABLED zone={zone} reason={reason}")

        # ------------------------------------------------------------
        # 3. Validate final zone activation map
        # ------------------------------------------------------------
        if not enriched_zones or all(len(z["interfaces"]) == 0 for z in enriched_zones.values()):
            e = EmptyActivationMapError()
            self.logger.error(f"Activation map invalid: {e}")
            return self._failure(e)

        # ------------------------------------------------------------
        # 4. Build activation components
        # ------------------------------------------------------------
        set_activation   = self.build_set_activation(enriched_zones)
        chain_activation = self.build_chain_activation()
        rule_activation  = self.build_rule_activation()

        # Normalize rule activation before validation
        rule_activation  = self.normalize_rule_activation(rule_activation)

        # Merge into a single activation_map
        activation_map = {
            "sets":   set_activation,
            "chains": chain_activation,
            "rules":  rule_activation,
        }

        # ------------------------------------------------------------
        # 5. Validate rule dependencies
        # ------------------------------------------------------------
        for idx, rule_data in activation_map["rules"].items():
            self.validate_rule_dependencies(
                rule_data,
                activation_map
            )
    
        # ------------------------------------------------------------
        # 6. Success
        # ------------------------------------------------------------
        self.logger.info("ActivationMapBuilder: build completed successfully")

        return {
            "success": True,
            "activation_map": activation_map,
        }

    # ----------------------------------------------------------------------
    # SET ACTIVATION PHASE (NEW)
    # ----------------------------------------------------------------------
    def build_set_activation(self, enriched_zones: dict) -> dict:
        """
        Convert zone activation → set activation.
        YAML-deterministic: sorted sets, sorted interfaces, sorted elements.
        """
        firewall_cfg = self.cfg.get("firewall", {})
        sets_cfg = firewall_cfg.get("sets", [])

        activation_map = {}

        # Sort sets by name for determinism
        for set_cfg in sorted(sets_cfg, key=lambda s: s["name"]):
            set_name = set_cfg["name"]
            zone = set_cfg.get("zone")

            zone_data = enriched_zones.get(zone, {})

            interfaces = sorted(zone_data.get("interfaces", []))
            ipv4_active = zone_data.get("ipv4_enabled", False)
            ipv6_active = zone_data.get("ipv6_enabled", False)
            required = set_cfg.get("required", False)
            kind = set_cfg.get("kind", "synthetic")
            if kind not in ("synthetic", "interface"):
                return self._failure(ValueError(f"Invalid kind for set {set_name}"))
            elif kind == "interface" and not zone:
                return self._failure(ValueError(f"Interface set {set_name} missing zone"))
            if kind == "interface":
                # interface sets are active only when interfaces exist
                active = bool(interfaces)
            else:
                # synthetic sets are never auto-active
                # they only become enforced if required=True
                active = False

            # Build activation-derived elements
            elements = self.build_activation_elements(
                set_cfg=set_cfg,
                interfaces=interfaces,
                ipv4_active=ipv4_active,
                ipv6_active=ipv6_active,
            )

            # Sort elements deterministically
            elements = sorted(
                elements,
                key=lambda e: e.get("addr") or e.get("port")
            )

            activation_map[set_name] = {
                "kind": kind,
                "active": active,
                "required": required,
                "ipv4_active": ipv4_active,
                "ipv6_active": ipv6_active,
                "interfaces": interfaces,
                "elements": elements,
            }

        return activation_map

    def build_chain_activation(self):
        """
        Build the chain activation map strictly from YAML.
        No semantic overrides, no backend logic, no synthetic chains.
        The Enforcer will later merge semantic truth and compute `active`.
        """
        activation = {}
        firewall_cfg = self.cfg.get("firewall", {})
        yaml_chains = firewall_cfg.get("chains", [])

        for c in yaml_chains:
            name = c["name"]

            activation[name] = {
                "hook": c.get("hook"),
                "type": c.get("type", "filter"),
                "priority": c.get("priority", 0),
                "required": c.get("required", False),
                "declared": True,   # came from YAML
                # no "active" here — Enforcer computes it
            }

        return activation

    def build_rule_activation(self):
        """
        Build rule activation strictly from YAML.
        No canonicalization, no backend logic.
        Keys are YAML indices.
        """

        activation = {}
        firewall_cfg = self.cfg.get("firewall", {})
        yaml_rules = firewall_cfg.get("rules", [])

        for idx, r in enumerate(yaml_rules):
            activation[idx] = {
                "order": idx,
                "declared": True,
                **r,
                "active": True,
                "required": True,
            }

        return activation

    # ----------------------------------------------------------------------
    # ACTIVATION ELEMENT BUILDER (NEW)
    # ----------------------------------------------------------------------
    def build_activation_elements(self, set_cfg, interfaces, ipv4_active, ipv6_active):
        """
        Build activation-derived elements:
        - interface IPv4/IPv6 subnets
        - interface gateways
        - dynamic trusted hosts (if applicable)
        """
       
        runtime = self.cfg.get("runtime", {})
        iface_info = runtime.get("iface_info", {})

        elements = []

        for iface in interfaces:
            info = iface_info.get(iface, {})

            # IPv4 subnet
            if ipv4_active and info.get("ipv4_subnet"):
                elements.append({"addr": info["ipv4_subnet"]})

            # IPv6 subnet
            if ipv6_active and info.get("ipv6_subnet"):
                elements.append({"addr": info["ipv6_subnet"]})

            # IPv4 gateway
            if ipv4_active and info.get("ipv4_gateway"):
                elements.append({"addr": info["ipv4_gateway"]})

            # IPv6 gateway
            if ipv6_active and info.get("ipv6_gateway"):
                elements.append({"addr": info["ipv6_gateway"]})

        return elements

    # ----------------------------------------------------------------------
    # FAILURE HANDLER
    # ----------------------------------------------------------------------
    def _failure(self, exception_obj):
        return {
            "success": False,
            "error": str(exception_obj),
            "type": type(exception_obj).__name__,
        }
        
    def validate_rule_dependencies(self, rule_data, activation_map):
        data = rule_data

        # chain
        chain = data["chain"]
        if chain not in activation_map["chains"]:
            raise ConfigError(f"Rule references unknown chain '{chain}'")
        activation_map["chains"][chain]["required"] = True

        # zones
        for zone_key in ("src_zone", "dst_zone"):
            zone = data.get(zone_key)
            if zone:
                if zone not in activation_map["sets"]:
                    raise ConfigError(f"Rule references unknown zone '{zone}'")
                activation_map["sets"][zone]["required"] = True

        # direct set reference
        set_name = data.get("set_name")
        if set_name:
            if set_name not in activation_map["sets"]:
                raise ConfigError(f"Rule references unknown set '{set_name}'")
            activation_map["sets"][set_name]["required"] = True
                
    def normalize_rule_activation(self, rule_activation):
        """
        Normalize rule activation entries so that every rule has a consistent,
        predictable set of semantic fields before dependency validation.
        """

        normalized = {}

        for name, data in rule_activation.items():
            if "chain" not in data:
                raise ConfigError(f"Rule '{name}' is missing required field 'chain'")

            # Normalize fields with defaults
            chain     = data["chain"]
            order     = data.get("order", 0)
            proto     = data.get("proto")
            action    = data.get("action", "accept")
            sport     = data.get("sport")
            dport     = data.get("dport")
            src_zone  = data.get("src_zone")
            dst_zone  = data.get("dst_zone")
            comment   = data.get("comment")

            # Type validation
            if not isinstance(chain, str):
                raise ConfigError(f"Rule '{name}' has invalid chain type (must be string)")

            if sport is not None and not isinstance(sport, int):
                raise ConfigError(f"Rule '{name}' sport must be an integer")

            if dport is not None and not isinstance(dport, int):
                raise ConfigError(f"Rule '{name}' dport must be an integer")

            if proto is not None and not isinstance(proto, str):
                raise ConfigError(f"Rule '{name}' proto must be a string")

            # Build normalized entry
            normalized[name] = {
                "chain": chain,
                "order": order,
                "proto": proto,
                "sport": sport,
                "dport": dport,
                "src_zone": src_zone,
                "dst_zone": dst_zone,
                "action": action,
                "comment": comment,
                # Preserve all original YAML fields for backend expression building
                **data,
            }

        return normalized

    def empty_activation(self):
        return {
            "active": False,
            "required": False,
            "elements": [],
        }
        