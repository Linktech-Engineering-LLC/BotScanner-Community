# BotScanner — Network Flow & Host Inspection Framework
![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-under--construction-yellow)
![NMS_Tools](https://img.shields.io/badge/Linktech-BotScanner-blueviolet)

BotScanner is a policy-driven, backend-agnostic firewall and system configuration manager.  
It enforces deterministic, audit-transparent rules across kernel parameters, nftables zones, and drift detection.

---

## Project Structure
- `etc/kernel.yml`  role-based sysctl configuration (IPv4 + IPv6).
- `etc/firewall.yml`  nftables zone definitions (dual-stack).
- `docs/kernel.md`  detailed kernel parameter documentation.
- `docs/firewall.md`  detailed firewall zone documentation.
- `docs/drift.md`  baseline, drift, and cross-drift documentation.
- `docs/enforcement.md`  enforcement modes, runtime enforcement, reload logic, and logging rules.
- `docs/logging.md`  operational guide for administrators to route and manage BotScanner logs.

---

## Quick Start
1. Clone the repository.
2. Review configs in `etc/`.
3. Apply kernel parameters with `sysctl -p etc/kernel.yml`.
4. Load firewall rules with `nft -f etc/firewall.yml`.
5. Run baseline capture and drift detection with BotScanner helpers.

---

## Documentation
- [Kernel Configuration](docs/kernel.md)
- [Firewall Configuration](docs/firewall.md)
- [Baseline / Drift / Cross-Drift](docs/drift.md)
- [Enforcement](docs/enforcement.md)
- [Logging Guide](docs/logging.md)
- [SSH Keys: Generation & Management](docs/ssh_keys.md)
- [SSH Config Examples](docs/ssh_config_examples.md)

---

## Roadmap
- Packaging (RPM/DEB or tarball).
- Additional zones (business, lab, departmental).
- Enforcement modes (`strict`, `audit-only`, `hybrid`).
- Integration with log parsers (Apache ? botblock).
- Baseline / Drift / Cross-Drift
  - Capture canonical baseline snapshots.
  - Detect drift against baseline with normalization.
  - Compare active backends for cross-drift consistency.
  - Lifecycle logging and audit-friendly artifacts.

## Contributor Workflow

To maintain audit transparency and consistency across BotScanner:

1. **Edit firewall.yml**
   - Add or adjust zone sets and chain rules.
   - Verify dual-stack coverage (IPv4 + IPv6).
   - Ensure botblock and trusted sets use correct flags and timeouts.

2. **Verify with nft**
   - Run `nft -f etc/firewall.yml` to load rules.
   - Confirm tables, sets, and chains are present with `nft list ruleset`.

3. **Update enforcement.md**
   - Document any new enforcement modes or rule changes.
   - Keep logging prefixes and rate-limits aligned with firewall.yml.

4. **Adjust logging.md**
   - If prefixes change, update rsyslog/syslog-ng/journald examples.
   - Ensure administrators can still route BOTBLOCK and DEFAULT logs cleanly.

5. **Review README.md**
   - Add links to new docs or configs.
   - Update roadmap if new subsystems or zones are introduced.

6. **Checklist alignment**
   - Mark completed items in the BotScanner Checklist.
   - Move pending tasks forward as theyre addressed.
