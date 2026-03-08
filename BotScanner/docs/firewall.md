# Firewall Configuration Documentation

This document describes the firewall zones, services, and enforcement modes used in **BotScanner**.

---

## Zones

### Public Zone
- **Purpose**: External/public-facing services.
- **Allowed services**: https (443/tcp), named (53/tcp+udp), ntp (123/udp).
- **Custom ports**: 2222 (SSH).
- **Dual-stack**: ipv4_addr + ipv6_addr sets.

### Home Zone
- **Purpose**: Internal LAN/Wi-Fi, semi-trusted.
- **Allowed services**: https, ntp, dns (optional).
- **Dual-stack**: ipv4_addr + ipv6_addr sets.

### Trusted Zone
- **Purpose**: Explicitly trusted hosts (/32 entries).
- **Notes**: Supports dynamic addition/removal with optional timeout.
- **Dual-stack**: ipv4_addr + ipv6_addr sets.

### Local Zone
- **Purpose**: Loopback and host-only traffic.
- **Dual-stack**: ipv4_addr + ipv6_addr sets.

### Botblock Zone
- **Purpose**: Dynamic blocklist populated from Apache logs.
- **Flags**: interval, timeout, dynamic, counter.
- **Attributes**: gc-interval 60s.
- **Dual-stack**: ipv4_addr + ipv6_addr sets.

---

## Enforcement Modes
- **Strict**: Apply all rules and drop unknown traffic.
- **Audit-only**: Log traffic without enforcement.
- **Hybrid**: Enforce known rules, log unknown traffic.
- **Fallback**: Unknown mode ? log error, default to strict.

---

## Notes
- All zones are defined dual-stack for audit transparency.
- IPv6 may be disabled at the kernel level (`net.ipv6.conf.all.disable_ipv6`), but sets remain defined for consistency.
- Service names are normalized (e.g., `https` instead of `apache2-ssl`).