"""
MacBook Fingerprint - Comprehensive macOS system fingerprinting tool.
"""

__version__ = "2.0.0"
__author__ = "MacBook Fingerprint Contributors"

from .core.fingerprint import create_fingerprint, hash_fingerprint
from .core.storage import save_fingerprint, load_fingerprint
from .core.comparison import compare_fingerprints

__all__ = [
    "create_fingerprint",
    "hash_fingerprint",
    "save_fingerprint",
    "load_fingerprint",
    "compare_fingerprints",
]
