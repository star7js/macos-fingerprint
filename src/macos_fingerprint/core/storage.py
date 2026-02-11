"""
Secure storage for fingerprint data.
"""

import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

from ..utils.commands import safe_write_file, safe_read_file, validate_json_safe
from ..utils.crypto import FingerprintEncryption, compute_integrity_hash


def save_fingerprint(
    fingerprint: Dict[str, Any],
    filename: str,
    encrypt: bool = False,
    password: Optional[str] = None,
) -> bool:
    """
    Save fingerprint to file with optional encryption.

    Args:
        fingerprint: Fingerprint dictionary
        filename: Output filename
        encrypt: Whether to encrypt the data
        password: Optional password for encryption

    Returns:
        True if successful, False otherwise
    """
    try:
        if encrypt:
            # Encrypt the fingerprint
            encryptor = FingerprintEncryption(password)
            encrypted_data = encryptor.encrypt(fingerprint)
            content = json.dumps(encrypted_data, indent=2)
        else:
            # Add integrity hash (password-derived when available)
            data_with_hash = fingerprint.copy()
            data_with_hash["_integrity_hash"] = compute_integrity_hash(
                fingerprint, password=password
            )
            content = json.dumps(data_with_hash, indent=2)

        # Write with secure permissions (0600)
        return safe_write_file(filename, content, permissions=0o600)
    except Exception as e:
        logger.error("Error saving fingerprint: %s", e)
        return False


def load_fingerprint(
    filename: str, encrypted: bool = False, password: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Load fingerprint from file with optional decryption.

    Args:
        filename: Input filename
        encrypted: Whether the data is encrypted
        password: Optional password for decryption

    Returns:
        Fingerprint dictionary or None on error
    """
    try:
        content = safe_read_file(filename)
        if not content:
            logger.error("File not found or could not be read: %s", filename)
            return None

        # Validate JSON before parsing
        validate_json_safe(content)
        data = json.loads(content)

        if encrypted:
            # Decrypt the fingerprint
            encryptor = FingerprintEncryption(password)
            fingerprint = encryptor.decrypt(data)
        else:
            # Verify integrity hash if present
            if "_integrity_hash" in data:
                stored_hash = data.pop("_integrity_hash")
                computed_hash = compute_integrity_hash(data, password=password)
                if stored_hash != computed_hash:
                    logger.warning("Integrity check failed - data may be corrupted")
            fingerprint = data

        return fingerprint
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in %s: %s", filename, e)
        return None
    except ValueError as e:
        logger.error("Error loading fingerprint: %s", e)
        return None
    except Exception as e:
        logger.error("Error loading fingerprint: %s", e)
        return None


def export_fingerprint(fingerprint: Dict[str, Any], filename: str) -> bool:
    """
    Export fingerprint to a file (convenience wrapper).

    Args:
        fingerprint: Fingerprint dictionary
        filename: Output filename

    Returns:
        True if successful, False otherwise
    """
    return save_fingerprint(fingerprint, filename, encrypt=False)
