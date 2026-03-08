# Import curated symbols from submodules
from .backend import FirewallBackend
from .firewalld import FirewalldBackend
from .nftables import NftablesBackend
# Optional: expose version metadata
__version__ = "0.2.0"
# Explicitly define the public API
__all__ = [
    "FirewallBackend",
    "FirewalldBackend",
    "NftablesBackend",
    "__version__",
]
