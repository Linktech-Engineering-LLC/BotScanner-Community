"""
BotScanner Package Initialization
---------------------------------
This file defines the public API surface of BotScanner.utils
Only names listed in __all__ are exported when using
`from botscanner import *`.

Audit Transparency:
- Every exported symbol is explicitly documented here.
- Internal helpers remain importable directly but are not
  part of the stable API contract.
"""

# Import curated symbols from submodules

from .factory import LoggerFactory
# Optional: expose version metadata
__version__ = "0.2.0"

# Explicitly define the public API
__all__ = [
    "LoggerFactory",
    "__version__",
]
