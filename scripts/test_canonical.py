import json

from BotScanner.firewall.backend.firewalld import FirewalldBackend
from BotScanner.firewall.backend.nftables import NftablesBackend

# --- Minimal config stubs ---
cfg = {
    "secrets": {"sudo_pass": "Ldm1120Vlm"},
    "firewall": {
        "backends": {
            "firewalld": {
                "command": "firewall-cmd",
                "capture": [
                    {"label": "zones", "cmd": "--list-all-zones"},
                    {"label": "services", "cmd": "--list-services"},
                    {"label": "direct_rules", "cmd": "--direct --get-all-rules"},
                    {"label": "nft_ruleset", "cmd": "!nft list ruleset"},
                ],
                "parse": "zones",
            },
            "nftables": {
                "command": "nft",
                "capture": [
                    {"label": "nft_ruleset", "cmd": "list ruleset"},
                ],
                "parse": "ruleset",
            },
        }
    }
}

# --- Minimal logger stub ---
class DummyLogger:
    def debug(self, msg): print(msg)
    def info(self, msg): print(msg)
    def warning(self, msg): print(msg)
    def error(self, msg): print(msg)

class DummyLoggerFactory:
    def get_logger(self, name): return DummyLogger()

lgr_cfg = {"factory": DummyLoggerFactory()}

# --- Instantiate backends ---
fw = FirewalldBackend(cfg, lgr_cfg)
nf = NftablesBackend(cfg, lgr_cfg)

# --- Print canonical output ---
print("\n=== FIREWALLD CANONICAL ===")
print(json.dumps(fw.canonicalize(), indent=2))

#print("\n=== NFTABLES CANONICAL ===")
#print(json.dumps(nf.canonicalize(), indent=2))