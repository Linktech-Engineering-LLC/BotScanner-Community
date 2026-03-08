"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-02-05
Modified: 2026-02-11
File: BotScanner/net/discovery.py
Description: Describe the purpose of this file
"""
# System Libraries
import os
import socket
import psutil
import ipaddress
import json
# Project Libraries
from .net_tools import local_command

class NetDiscovery:
    def __init__(self, cfg: dict, lgr_cfg: dict):
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg
        # Logger factory is passed in via lgr_cfg
        self.logger_factory = lgr_cfg.get("factory")
        self.logger = self.logger_factory.get_logger("netdiscovery")

    @staticmethod
    def build_iface_info(live_ifaces):
        info = {}

        addrs = psutil.net_if_addrs()
        gw_map = NetDiscovery.discover_gateways()

        for iface, data in live_ifaces.items():
            iface_info = {
                "ipv4_enabled": False,
                "ipv6_enabled": False,
                "subnets": [],
                "gateways": gw_map.get(iface, [])
            }

            for addr in addrs.get(iface, []):
                # IPv4
                if addr.family == socket.AF_INET:
                    iface_info["ipv4_enabled"] = True
                    iface_info["subnets"].append(
                        str(ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False))
                    )

                # IPv6
                elif addr.family == socket.AF_INET6:
                    if not addr.address.startswith("fe80"):
                        iface_info["ipv6_enabled"] = True
                        iface_info["subnets"].append(
                            str(ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False))
                        )

            info[iface] = iface_info

        return info

    @staticmethod
    def build_runtime(logger):
        # ------------------------------------------------------------
        # 1. Discover link-layer interfaces
        # ------------------------------------------------------------
        ip_link, rc, err = local_command("ip -j link")
        if rc != 0:
            logger.error("Unable to detect Live Interfaces")
            return {}

        link_data = json.loads(ip_link)

        live_ifaces = []
        bridges = {}
        iface_info = {}

        for entry in link_data:
            name = entry.get("ifname")
            if not name:
                continue

            live_ifaces.append(name)

            iface_info[name] = {
                "mtu": entry.get("mtu"),
                "state": entry.get("operstate"),
                "master": entry.get("master"),
                "flags": entry.get("flags", []),

                # Address-layer fields (populated later)
                "ipv4": [],
                "ipv6": [],
                "ipv4_enabled": False,
                "ipv6_enabled": False,
                "subnets": [],
                "gateways": [],
            }

        # ------------------------------------------------------------
        # 2. Discover IPv4/IPv6 addresses
        # ------------------------------------------------------------
        ip_addr, rc, err = local_command("ip -j addr")
        if rc != 0:
            logger.error("Unable to detect IP addresses")
            return {}

        addr_data = json.loads(ip_addr)

        for entry in addr_data:
            name = entry.get("ifname")
            if name not in iface_info:
                continue

            addr_info = iface_info[name]

            for addr in entry.get("addr_info", []):
                family = addr.get("family")
                local = addr.get("local")
                prefix = addr.get("prefixlen")

                if not local or prefix is None:
                    continue

                # Skip loopback IPv4 entirely
                if family == "inet" and local.startswith("127."):
                    continue

                # Convert host → network CIDR
                try:
                    net = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
                    cidr = str(net)
                except Exception:
                    logger.error(f"[RUNTIME] Invalid subnet: {local}/{prefix}")
                    continue

                if family == "inet":
                    addr_info["ipv4"].append(cidr)
                    addr_info["subnets"].append(cidr)
                    addr_info["ipv4_enabled"] = True

                elif family == "inet6":
                    # Skip link-local IPv6 (optional)
                    if local.startswith("fe80:"):
                        continue

                    addr_info["ipv6"].append(cidr)
                    addr_info["subnets"].append(cidr)
                    addr_info["ipv6_enabled"] = True

        # ------------------------------------------------------------
        # 3. Detect bridges (master → slaves)
        # ------------------------------------------------------------
        for iface, info in iface_info.items():
            master = info.get("master")
            if master:
                if master not in bridges:
                    bridges[master] = {"slaves": []}
                bridges[master]["slaves"].append(iface)

        # ------------------------------------------------------------
        # 4. Logging for diagnostics
        # ------------------------------------------------------------
        logger.info(f"[RUNTIME] live_ifaces={live_ifaces}")
        logger.info(f"[RUNTIME] bridges={bridges}")
        logger.info(f"[RUNTIME] iface_info keys={list(iface_info.keys())}")

        # ------------------------------------------------------------
        # 5. Return full runtime structure
        # ------------------------------------------------------------
        return {
            "live_interfaces": live_ifaces,
            "bridges": bridges,
            "iface_info": iface_info,
        }

    @staticmethod
    def detect_ipv6_capability():
        try:
            with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
                if f.read().strip() == "1":
                    return False
        except FileNotFoundError:
            pass

        # If the file exists and is 0, IPv6 is enabled
        return True

                       
    # -----------------------------
    # Bridge detection (v2 logic)
    # -----------------------------
    @staticmethod
    def discover_bridges():
        bridges = {}

        net_path = "/sys/class/net"
        if not os.path.isdir(net_path):
            return bridges

        for iface in os.listdir(net_path):
            br_path = os.path.join(net_path, iface, "brif")
            if os.path.isdir(br_path):
                slaves = os.listdir(br_path)
                bridges[iface] = slaves

        return bridges

    # -----------------------------
    # Gateway detection (v2 logic)
    # -----------------------------
    @staticmethod
    def discover_gateways():
        """
        Returns a mapping: iface -> [gateway_ip]
        Only captures IPv4 default gateways for now.
        """
        gw_map = {}

        out, rc, err = local_command("ip route")

        if rc != 0:
            return gw_map  # empty but safe

        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue

            # Match: default via 192.168.0.1 dev br0
            if parts[0] == "default" and "via" in parts and "dev" in parts:
                try:
                    gw = parts[parts.index("via") + 1]
                    dev = parts[parts.index("dev") + 1]

                    # Validate IPv4
                    ipaddress.IPv4Address(gw)

                    gw_map.setdefault(dev, []).append(gw)

                except Exception:
                    # Ignore malformed lines
                    continue

        return gw_map

    @staticmethod
    def discover_live_interfaces():
        live = {}

        for iface, addrs in psutil.net_if_addrs().items():
            if ":" in iface:
                continue
            iface_data = {
                "ipv4": [],
                "ipv6": [],
                "mac": None,
                "flags": []
            }

            for addr in addrs:
                if addr.family.name == socket.AF_INET:
                    iface_data["ipv4"].append(addr.address)
                elif addr.family.name == socket.AF_INET6:
                    # Skip link-local unless you want them
                    if not addr.address.startswith("fe80"):
                        iface_data["ipv6"].append(addr.address)
                elif addr.family.name == psutil.AF_LINK:
                    iface_data["mac"] = addr.address

            live[iface] = iface_data

        return live


    # -----------------------------
    # Subnet + interface discovery
    # -----------------------------

    def get_local_subnets() -> dict[str, list[str]]:
        """
        Return local subnets grouped by type and family.
        {
        "loopback_v4": [...],
        "loopback_v6": [...],
        "trusted_v4": [...],
        "trusted_v6": [...]
        }
        """
        subnets = {
            "loopback_v4": [],
            "loopback_v6": [],
            "trusted_v4": [],
            "trusted_v6": []
        }

        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == "AF_INET":
                    network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                    if iface == "lo" or str(network).startswith("127."):
                        subnets["loopback_v4"].append(str(network))
                    else:
                        subnets["trusted_v4"].append(str(network))

                elif addr.family.name == "AF_INET6":
                    ip = addr.address.split("%")[0]  # strip scope id
                    network = ipaddress.ip_network(f"{ip}/{addr.netmask}", strict=False)
                    if iface == "lo" or str(network).startswith("::1"):
                        subnets["loopback_v6"].append(str(network))
                    else:
                        subnets["trusted_v6"].append(str(network))

        return subnets

    # -----------------------------
    # IPv6 capability detection
    # -----------------------------
    def system_supports_ipv6(self) -> bool:
        # kernel disable flag
        try:
            with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
                if f.read().strip() == "1":
                    return False
        except FileNotFoundError:
            return False

        # interface-level IPv6 presence
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == "AF_INET6":
                    ip = addr.address.split("%")[0]
                    if ip not in ("::1",) and not ip.startswith("fe80:"):
                        return True

        return False

    @staticmethod
    def is_valid_ip(addr: str) -> bool:
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False


