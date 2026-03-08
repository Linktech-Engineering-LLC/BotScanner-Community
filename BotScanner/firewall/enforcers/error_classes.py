"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-18
Modified: 2026-01-18
File: BotScanner/firewall/enforcers/error_classes.py
Description: Custom exception hierarchy for BotScanner's activation map Builder
and enforcement pipeline. These exceptions are raised by helpers
and caught by the Builder, which logs them and returns structured
failure objects to the orchestrator.
"""
# System Libraries
# Project Libraries

# ------------------------------------------------------------
# Base class
# ------------------------------------------------------------
class ActivationMapError(Exception):
    """Base class for all activation map and Builder-related errors."""
    pass


# ------------------------------------------------------------
# Zone / Interface Mapping Errors
# ------------------------------------------------------------
class ZoneMappingError(ActivationMapError):
    """Base class for zone/interface mapping errors."""
    pass


class DuplicateInterfaceError(ZoneMappingError):
    """Interface assigned to multiple zones."""
    def __init__(self, iface, zones):
        super().__init__(f"Interface '{iface}' assigned to multiple zones: {zones}")
        self.iface = iface
        self.zones = zones


class UnknownZoneError(ZoneMappingError):
    """YAML references a zone not defined in activation_map_v1."""
    def __init__(self, zone):
        super().__init__(f"Unknown zone referenced: '{zone}'")
        self.zone = zone


class InvalidInterfaceError(ZoneMappingError):
    """YAML references an interface not present on the host."""
    def __init__(self, iface):
        super().__init__(f"Interface '{iface}' not present on host")
        self.iface = iface


class BridgeConflictError(ZoneMappingError):
    """Bridge master and slave assigned to conflicting zones."""
    def __init__(self, master, slave, master_zone, slave_zone):
        msg = (
            f"Bridge conflict: master '{master}' is in zone '{master_zone}', "
            f"but slave '{slave}' is in zone '{slave_zone}'"
        )
        super().__init__(msg)
        self.master = master
        self.slave = slave
        self.master_zone = master_zone
        self.slave_zone = slave_zone

# ------------------------------------------------------------
# IP Detection Errors
# ------------------------------------------------------------
class IPDetectionError(ActivationMapError):
    """Base class for IP detection and parsing errors."""
    pass


class InvalidIPv4Error(IPDetectionError):
    """Malformed IPv4 address or mask."""
    def __init__(self, iface, address, netmask):
        super().__init__(f"Invalid IPv4 on {iface}: {address}/{netmask}")
        self.iface = iface
        self.address = address
        self.netmask = netmask


class InvalidIPv6Error(IPDetectionError):
    """Malformed IPv6 address or prefix."""
    def __init__(self, iface, address, prefix):
        super().__init__(f"Invalid IPv6 on {iface}: {address}/{prefix}")
        self.iface = iface
        self.address = address
        self.prefix = prefix


# ------------------------------------------------------------
# Builder-Level Errors
# ------------------------------------------------------------
class BuilderFailure(ActivationMapError):
    """General Builder failure when a valid activation map cannot be produced."""
    pass

class ConfigError(Exception):
    """Raised when the firewall configuration is invalid."""
    pass

class EmptyActivationMapError(BuilderFailure):
    """Builder produced no active zones or interfaces."""
    def __init__(self):
        super().__init__("Activation map is empty; no zones or interfaces are active")
