# Enforcement Documentation

This document describes how BotScanner enforces firewall and kernel configurations, including runtime checks and reload logic.

---

## Enforcement Modes
- **Strict**: Apply all rules, drop unknown traffic.
- **Audit-only**: Log traffic without enforcement.
- **Hybrid**: Enforce known rules, log unknown traffic.
- **Fallback**: Unknown mode ? log error, default to strict.

---

## Runtime Enforcement
- **Zone enforcement**: Apply rules for public, home, trusted, local, and botblock zones.
- **Service mapping**: Translate service names (https, ntp, named) into ports/protocols.
- **Dual-stack enforcement**: Apply rules to both IPv4 and IPv6 sets.

---

## Reload Logic
- **Detection**: On startup, check if expected tables (e.g. `inet botscanner`) exist.
- **Restore**: If missing, look for `etc/nftables.nft` and reload with:
- **Verification**: After reload, list tables/sets/chains to confirm consistency.
- **Logging**: Append-only lifecycle logs:

---

## Notes
- Enforcement is separate from drift detection.
- Reload logic ensures persistence without relying on system services.
- Audit transparency maintained through deterministic logging.

## Logging and Drop Enforcement

### Botblock
- Rule: `ip saddr @botblock log prefix 'BOTBLOCK' limit rate 10/second counter drop`
- Purpose: Explicitly log and count packets from known malicious sources.
- Logging: Sent to syslog/journald with prefix `BOTBLOCK`.
- Counters: Maintained in nftables for audit.

### Default Deny
- Rule: `log prefix 'DEFAULT' limit rate 10/second counter drop`
- Purpose: Catch-all deny for any traffic not explicitly permitted.
- Logging: Sent to syslog/journald with prefix `DEFAULT`.
- Counters: Maintained in nftables for audit.
- Note: Rate limiting prevents log flooding under heavy traffic.

### Log Routing
- By default, logs are collected by journald/syslog.
- Administrators may configure external logging daemons (e.g. rsyslog, syslog-ng) to filter on
  the `BOTBLOCK` and `DEFAULT` prefixes and route them into separate files if desired.
- Such routing is external to BotScanner; enforcement only guarantees that logs are emitted
  with deterministic prefixes and counters.
- See `docs/logging.md` for operational examples of rsyslog/syslog-ng and journald filtering.