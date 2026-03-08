# Kernel Configuration Documentation

This document describes the kernel sysctl parameters used in **BotScanner**, organized by role and protocol stack.

---

## IPv4 Parameters

### IP Forwarding
- **Key**: `net.ipv4.ip_forward`
- **Roles**:
  - Router: `1` (forwarding enabled)
  - Server: `0`
  - Workstation: `0`

### Reverse Path Filtering
- **Keys**:  
  - `net.ipv4.conf.all.rp_filter`  
  - `net.ipv4.conf.default.rp_filter`
- **Roles**: router, server, workstation ? `1`

### Redirect Handling
- **Keys**:  
  - `net.ipv4.conf.all.accept_redirects`  
  - `net.ipv4.conf.default.accept_redirects`  
  - `net.ipv4.conf.all.send_redirects`  
  - `net.ipv4.conf.default.send_redirects`
- **Roles**: all ? `0`

### Source Routing
- **Keys**:  
  - `net.ipv4.conf.all.accept_source_route`  
  - `net.ipv4.conf.default.accept_source_route`
- **Roles**: all ? `0`

---

## IPv6 Parameters

### IPv6 Enable/Disable
- **Keys**:  
  - `net.ipv6.conf.all.disable_ipv6`  
  - `net.ipv6.conf.default.disable_ipv6`
- **Roles**:
  - Router: `0` (enabled)
  - Server: `0` (enabled)
  - Workstation: `1` (disabled)

### IPv6 Forwarding
- **Key**: `net.ipv6.conf.all.forwarding`
- **Roles**:
  - Router: `1`
  - Server: `0`
  - Workstation: `0`

### Redirect Handling
- **Keys**:  
  - `net.ipv6.conf.all.accept_redirects`  
  - `net.ipv6.conf.default.accept_redirects`
- **Roles**: all ? `0`

### Source Routing
- **Keys**:  
  - `net.ipv6.conf.all.accept_source_route`  
  - `net.ipv6.conf.default.accept_source_route`
- **Roles**: all ? `0`

### Router Advertisements
- **Keys**:  
  - `net.ipv6.conf.all.accept_ra`  
  - `net.ipv6.conf.default.accept_ra`
- **Roles**:
  - Router: `0` (routers should not accept RAs)
  - Server: `0` (tightened baseline)
  - Workstation: `0` (tightened baseline)

---

## Notes
- All parameters are defined role-by-role for audit transparency.  
- IPv6 sets remain defined even if disabled locally, ensuring deterministic configs across hosts.  
- Structure mirrors IPv4 for consistency.  
- Enforcement is handled via `kernel.yml` in `etc/`.
