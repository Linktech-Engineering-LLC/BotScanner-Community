# Service Checks and Validation

BotScanner can verify that important system services are running and that their
required ports are correctly exposed through the firewall.

This document explains how to configure and use service validation.

---

## Declaring Services in hosts.yml

Each host may declare a list of services: and to enable the service checks, check must be set to  true, if check is missing it defaults to false

```yaml
services:
  - name: apache
    check: true
  - name: sshd
    check: true
  - name: fail2ban
    check: false

What Service Validation Does

When enabled, BotScanner will:
    - Confirm the service is defined in services.yml
    - Check whether the service's daemon is running
    - Check whether the service is enabled at boot
    - Compare expected ports against the firewall
    - Log any mismatches

This helps detect issues such as:
    - Apache crashing
    - SSH not running
    - Required ports not exposed
    - Unexpected ports exposed

Enabling or Disabling Validation
Globally:
applications:
  BotScanner:
    service_validation: true

Per service:
services:
  - name: apache
    check: true

Logs
## Results are written to:
Logs/<basename>.log

## Examples:
- SERVICE-RUNNING
- SERVICE-NOT-RUNNING
- PORT-MISSING
- PORT-UNEXPECTED-OPEN

## End of Document


