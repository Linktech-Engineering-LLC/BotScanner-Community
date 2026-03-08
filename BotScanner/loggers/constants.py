"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2025-12-26
Modified: 2026-01-10
File: BotScanner/loggers/constants.py
Description: Constants that are used in logging functions
"""
# Lifecycle Constants
class LifecycleEvents:
    ADD_TO_SET = "ADD_TO_SET"
    CLEANUP = "CLEANUP"
    CMD_START = "CMD_START"
    COMPLETE = "COMPLETE"
    CONFIG_CHECK = "CONFIG_CHECK"
    CONFIG_RESOLVED = "CONFIG_RESOLVED"
    CMD_END = "CMD_END"
    CROSS = "CROSS"
    CROSS_DRIFT_FOUND = "CROSS_DRIFT_FOUND"
    END_RUN = "END_RUN"
    ENFORCE = "ENFORCE"
    INIT = "INIT"
    LOADER_SETUP = "LOADER_SETUP"
    START_RUN = "START_RUN"
    DRIFT = "DRIFT"
    STATUS = "STATUS"
    SKIP = "SKIP"
    RECREATE = "RECREATE"

LIFECYCLE_EVENTS = {
    LifecycleEvents.ADD_TO_SET,
    LifecycleEvents.CLEANUP, 
    LifecycleEvents.CMD_START, 
    LifecycleEvents.CMD_END, 
    LifecycleEvents.COMPLETE,
    LifecycleEvents.CONFIG_CHECK, 
    LifecycleEvents.CONFIG_RESOLVED, 
    LifecycleEvents.CROSS,
    LifecycleEvents.CROSS_DRIFT_FOUND,
    LifecycleEvents.END_RUN,
    LifecycleEvents.ENFORCE, 
    LifecycleEvents.INIT, 
    LifecycleEvents.LOADER_SETUP, 
    LifecycleEvents.START_RUN, 
    LifecycleEvents.DRIFT, 
    LifecycleEvents.CROSS, 
    LifecycleEvents.SKIP, 
    LifecycleEvents.RECREATE, 
    LifecycleEvents.DRIFT
}

