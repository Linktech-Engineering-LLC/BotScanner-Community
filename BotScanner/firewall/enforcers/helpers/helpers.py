"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-18
Modified: 2026-02-07
File: BotScanner/firewall/enforcers/helpers.py
Description: Helper routines for zone/interface validation and IPv4/IPv6 detection. 
These helpers remain pure: they raise structured exceptions for fatal 
errors and log only recoverable anomalies. The Builder is responsible 
for catching exceptions and logging fatal failures.
"""
# System Libraries
import ipaddress
# Project Libraries
from ..error_classes import (
    DuplicateInterfaceError,
    InvalidInterfaceError,
    UnknownZoneError,
    BridgeConflictError,
    InvalidIPv4Error,
    InvalidIPv6Error,
)
# ------------------------------------------------------------
# Zone / Interface Validation
# ------------------------------------------------------------
def validate_zone_interface_mapping(yaml_ifaces, live_ifaces, bridges, logger):
    """
    Validate and normalize zone→interface assignments.

    Returns:
        zone_map: dict(zone -> sorted list of interfaces)

    Raises:
        DuplicateInterfaceError
        InvalidInterfaceError
        UnknownZoneError
        BridgeConflictError
    """

    zone_map = {}
    iface_to_zone = {}

    # ------------------------------------------------------------
    # 1. YAML zone assignments (masters + explicit slaves)
    # ------------------------------------------------------------
    for entry in yaml_ifaces:
        names = entry.get("names", [])
        zone = entry.get("zone")
        slaves = entry.get("slaves", [])

        if not zone:
            raise UnknownZoneError(f"Missing zone for entry: {entry}")

        # Assign masters
        for iface in names:
            if iface not in live_ifaces:
                logger.info(f"Skipping iface '{iface}' (not present on this host)")
                continue

            if iface in iface_to_zone:
                if iface_to_zone[iface] != zone:
                    raise DuplicateInterfaceError(iface, [iface_to_zone[iface], zone])
                continue  # already assigned correctly

            iface_to_zone[iface] = zone
            zone_map.setdefault(zone, []).append(iface)

        # Assign YAML-defined slaves
        for slave in slaves:
            if slave not in live_ifaces:
                logger.warning(f"YAML references slave '{slave}' not present on host")
                raise InvalidInterfaceError(slave)

            if slave in iface_to_zone:
                if iface_to_zone[slave] != zone:
                    raise BridgeConflictError(names[0], slave, zone, iface_to_zone[slave])
                continue  # already assigned correctly

            iface_to_zone[slave] = zone
            zone_map.setdefault(zone, []).append(slave)

    # ------------------------------------------------------------
    # 2. Bridge inheritance (runtime-discovered slaves)
    # ------------------------------------------------------------
    for master, slave_info in bridges.items():
        if master not in live_ifaces:
            continue

        master_zone = iface_to_zone.get(master)
        if not master_zone:
            logger.warning(f"Bridge master '{master}' has no zone assignment")
            continue

        slave_list = slave_info.get("slaves", [])

        for slave in slave_list:
            if slave not in live_ifaces:
                logger.warning(f"Bridge slave '{slave}' not present on host")
                continue

            if slave in iface_to_zone:
                if iface_to_zone[slave] != master_zone:
                    raise BridgeConflictError(master, slave, master_zone, iface_to_zone[slave])
                continue  # already assigned correctly

            iface_to_zone[slave] = master_zone
            zone_map.setdefault(master_zone, []).append(slave)

    # ------------------------------------------------------------
    # 3. Canonicalize output
    # ------------------------------------------------------------
    for zone in zone_map:
        zone_map[zone] = sorted(set(zone_map[zone]))

    return zone_map

# ------------------------------------------------------------
# IPv4 / IPv6 Detection
# ------------------------------------------------------------
def detect_ip_families(zone_map, iface_info, logger):
    """
    Preserve zone_map structure and augment with IPv4/IPv6 detection.
    """

    enriched = {}

    for zone, ifaces in zone_map.items():
        v4_subnets = set()
        v4_gateways = set()
        v6_subnets = set()
        v6_gateways = set()

        for iface in ifaces:
            info = iface_info.get(iface, {})

            # IPv4
            for cidr in info.get("ipv4", []):
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    v4_subnets.add(str(net))
                except Exception:
                    logger.error(f"Invalid IPv4 subnet on {iface}: {cidr}")
                    raise InvalidIPv4Error(iface, cidr)

            # IPv6
            for cidr in info.get("ipv6", []):
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except Exception:
                    logger.error(f"Invalid IPv6 subnet on {iface}: {cidr}")
                    raise InvalidIPv6Error(iface, cidr)

                # Skip link-local
                if net.is_link_local:
                    logger.debug(f"Skipping link-local IPv6 on {iface}: {net}")
                    continue

                v6_subnets.add(str(net))

        enriched[zone] = {
            "interfaces": sorted(ifaces),
            "ipv4_enabled": bool(v4_subnets),
            "ipv6_enabled": bool(v6_subnets),
            "v4": {
                "subnets": sorted(v4_subnets),
                "gateways": sorted(v4_gateways),
            },
            "v6": {
                "subnets": sorted(v6_subnets),
                "gateways": sorted(v6_gateways),
            },
        }

    return enriched

def assign_yaml_interfaces_to_zones(yaml_ifaces, live_ifaces, logger):
    """
    Returns a dict:
        { zone_name: [iface1, iface2, ...] }
    """

    zone_map = {}

    # Initialize zones
    for entry in yaml_ifaces:
        zone = entry["zone"]
        zone_map.setdefault(zone, [])

    # Match YAML names to runtime interfaces
    for entry in yaml_ifaces:
        zone = entry["zone"]
        yaml_names = entry.get("names", [])
        slaves = entry.get("slaves", [])

        for yaml_name in yaml_names:
            for live_name, info in live_ifaces.items():
                altnames = info.get("altnames", [])

                if yaml_name == live_name or yaml_name in altnames:
                    if live_name not in zone_map[zone]:
                        zone_map[zone].append(live_name)
                        logger.info(f"Assigned iface={live_name} to zone={zone}")

        # Bridge slave support
        for slave in slaves:
            if slave in live_ifaces:
                if slave not in zone_map[zone]:
                    zone_map[zone].append(slave)
                    logger.info(f"Assigned slave iface={slave} to zone={zone}")

    return zone_map
