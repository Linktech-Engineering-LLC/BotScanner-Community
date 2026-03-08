"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-03
Modified: 2026-01-25
File: BotScanner/firewall/backend/detect.py
Description: Describe the purpose of this file
"""
# System Libraries
import os
import shutil
from enum import Enum
from dataclasses import dataclass
# Project Libraries
from BotScanner.net import sudo_run

class KernelBackend(Enum):
    NFTABLES = "nftables"
    UNKNOWN = "unknown"
class ManagerBackend(Enum):
    FIREWALLD = "firewalld"
    UFW = "ufw"
    NONE = "none"
    UNKNOWN = "unknown"
@dataclass
class BackendSelection:
    kernel: KernelBackend
    manager: ManagerBackend


def _firewalld_available(sudo_password: str) -> bool:
    return (
        os.path.exists("/usr/bin/firewall-cmd")
        and _firewalld_running(sudo_password)
    )

def _firewalld_running(sudo_password: str) -> bool:
    result = sudo_run("firewall-cmd --state", sudo_password)
    return result.code == 0


def detect_kernel_backend(sudo_password: str) -> KernelBackend:
    """
    Detect the REAL active kernel firewall backend using sudo_run.
    This inspects runtime behavior, not installed binaries.
    """

    # ------------------------------------------------------------
    # 1. Check if nftables is active (strongest signal)
    # ------------------------------------------------------------
    nft = sudo_run("nft list ruleset", sudo_password)
    if nft.code == 0:
        # nftables is active and authoritative
        return KernelBackend.NFTABLES

    # ------------------------------------------------------------
    # 2. Check if firewalld is running (always implies nftables)
    # ------------------------------------------------------------
    fw = sudo_run("systemctl is-active firewalld", sudo_password)
    if fw.code == 0 and fw.msg.strip() == "active":
        return KernelBackend.NFTABLES

    # ------------------------------------------------------------
    # 3. Nothing detected
    # ------------------------------------------------------------
    return KernelBackend.UNKNOWN

def detect_manager_backend(sudo_password: str) -> ManagerBackend:
    """
    Detect the active firewall MANAGER backend using sudo_run.
    This identifies the tool controlling the firewall, not the kernel backend.
    """

    # ------------------------------------------------------------
    # 1. firewalld (highest priority)
    # ------------------------------------------------------------
    fw = sudo_run("systemctl is-active firewalld", sudo_password)
    if fw.code == 0 and "active" in fw.msg.lower():
        return ManagerBackend.FIREWALLD

    # ------------------------------------------------------------
    # 2. ufw (Ubuntu systems)
    # ------------------------------------------------------------
    ufw = sudo_run("ufw status", sudo_password)
    if ufw.code == 0 and ("active" in ufw.msg.lower() or "inactive" in ufw.msg.lower()):
        # ufw is installed and responding
        return ManagerBackend.UFW

    # ------------------------------------------------------------
    # 3. No manager detected
    # ------------------------------------------------------------
    return ManagerBackend.NONE

def select_backends(sudo_password: str) -> BackendSelection:
    kernel = detect_kernel_backend(sudo_password)
    manager = detect_manager_backend(sudo_password)

    # Safety rule: firewalld always implies nftables
    if manager == ManagerBackend.FIREWALLD and kernel != KernelBackend.NFTABLES:
        # Force correction
        kernel = KernelBackend.NFTABLES

    # Safety rule: ufw may use either backend, no correction needed

    return BackendSelection(kernel=kernel, manager=manager)
