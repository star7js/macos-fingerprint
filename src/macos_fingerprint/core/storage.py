"""
Secure storage for fingerprint data.
"""

import json
import os
from typing import Dict, Any, Optional

from ..utils.commands import safe_write_file, safe_read_file, validate_json_safe
from ..utils.crypto import FingerprintEncryption, compute_integrity_hash


def save_fingerprint(
    fingerprint: Dict[str, Any],
    filename: str,
    encrypt: bool = False,
    password: Optional[str] = None
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
            # Add integrity hash
            data_with_hash = fingerprint.copy()
            data_with_hash['_integrity_hash'] = compute_integrity_hash(fingerprint)
            content = json.dumps(data_with_hash, indent=2)

        # Write with secure permissions (0600)
        return safe_write_file(filename, content, permissions=0o600)
    except Exception as e:
        print(f"Error saving fingerprint: {e}")
        return False


def load_fingerprint(
    filename: str,
    encrypted: bool = False,
    password: Optional[str] = None
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
            print(f"Error: {filename} not found or could not be read.")
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
            if '_integrity_hash' in data:
                stored_hash = data.pop('_integrity_hash')
                computed_hash = compute_integrity_hash(data)
                if stored_hash != computed_hash:
                    print("Warning: Integrity check failed - data may be corrupted")
            fingerprint = data

        return fingerprint
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {filename}: {e}")
        return None
    except ValueError as e:
        print(f"Error loading fingerprint: {e}")
        return None
    except Exception as e:
        print(f"Error loading fingerprint: {e}")
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
