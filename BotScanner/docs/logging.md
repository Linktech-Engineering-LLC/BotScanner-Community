# Logging Configuration Guide

This document provides operational guidance for administrators on how to route and manage
BotScanner firewall logs. It complements `enforcement.md` but is not part of enforcement logic.

---

## Default Behavior
- nftables `log` expressions emit kernel log messages.
- By default, these are collected by systemd-journald and/or syslog daemons.
- Messages appear in `journalctl -k` or `/var/log/messages` depending on system setup.

---

## Log Prefixes
- **BOTBLOCK** ? packets dropped due to botblock set.
- **DEFAULT** ? packets dropped by catch-all deny rule.
- Both are rate-limited (10/second) and include counters.

---

## Journald Usage
- View logs directly:
  ```bash
  journalctl -k | grep BOTBLOCK
  journalctl -k | grep DEFAULT

---
## rsyslog Configuration
# /etc/rsyslog.d/30-nftables.conf

:msg, contains, "BOTBLOCK" /var/log/nftables-botblock.log
:msg, contains, "DEFAULT"  /var/log/nftables-default.log

& ~

## syslog-ng Configuration
filter f_botblock { match("BOTBLOCK" value("MESSAGE")); };
filter f_default  { match("DEFAULT" value("MESSAGE")); };

log { source(src); filter(f_botblock); destination(d_botblock); };
log { source(src); filter(f_default);  destination(d_default); };
