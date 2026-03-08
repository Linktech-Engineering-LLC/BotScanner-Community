"""
BotScanner Package Initialization
---------------------------------
This file defines the public API surface of BotScanner.loader
Only names listed in __all__ are exported when using
`from botscanner import *`.

Audit Transparency:
- Every exported symbol is explicitly documented here.
- Internal helpers remain importable directly but are not
  part of the stable API contract.
"""

# Import curated symbols from submodules

from .configloader import ConfigLoader
from .config_resolver import ConfigResolver
from .vault_loader import VaultLoader

# Optional: expose version metadata
__version__ = "0.2.0"

# Explicitly define the public API
__all__ = [
    "ConfigLoader",
    "ConfigResolver",
    "VaultLoader",
    "__version__"
]
