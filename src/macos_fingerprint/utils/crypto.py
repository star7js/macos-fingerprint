"""
Cryptographic utilities for hashing and encrypting sensitive fingerprint data.
"""

import hashlib
import hmac
import json
import secrets
import base64
from typing import Any, Callable, Dict, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def hash_sensitive_value(value: str, algorithm: str = "sha3_256") -> str:
    """
    Hash a sensitive value using SHA-3 (Keccak) for quantum-resistance consideration.

    Args:
        value: The value to hash
        algorithm: Hashing algorithm (default: sha3_256)

    Returns:
        Hex-encoded hash string
    """
    if not value:
        return ""

    hasher = hashlib.new(algorithm)
    hasher.update(value.encode("utf-8"))
    return hasher.hexdigest()


def _hash_network_config(net_config: Dict[str, Any]) -> Dict[str, Any]:
    """Hash sensitive fields within a network config dict."""
    net_config = net_config.copy()

    if "ip_addresses" in net_config and isinstance(net_config["ip_addresses"], dict):
        net_config["ip_addresses"] = {
            service: hash_sensitive_value(ip)
            for service, ip in net_config["ip_addresses"].items()
        }

    if "arp_cache" in net_config and isinstance(net_config["arp_cache"], list):
        net_config["arp_cache"] = [
            hash_sensitive_value(line) if line else ""
            for line in net_config["arp_cache"]
        ]

    if "routing_table" in net_config and isinstance(net_config["routing_table"], list):
        net_config["routing_table"] = [
            hash_sensitive_value(line) if line else ""
            for line in net_config["routing_table"]
        ]

    if "wifi_networks" in net_config and isinstance(net_config["wifi_networks"], list):
        net_config["wifi_networks"] = [
            hash_sensitive_value(line) if line else ""
            for line in net_config["wifi_networks"]
        ]

    return net_config


def _hash_ssh_config(ssh_config: Dict[str, Any]) -> Dict[str, Any]:
    """Hash sensitive fields within an SSH config dict."""
    ssh_config = ssh_config.copy()
    if "known_hosts" in ssh_config and isinstance(ssh_config["known_hosts"], list):
        ssh_config["known_hosts"] = [
            hash_sensitive_value(line) if line else ""
            for line in ssh_config["known_hosts"]
        ]
    return ssh_config


def _hash_hosts_file(hosts_data: list) -> list:
    """Hash non-comment entries in a hosts file list."""
    return [
        hash_sensitive_value(line) if line and not line.startswith("#") else line
        for line in hosts_data
    ]


# Map collector names to the hashing function for their data.
_COLLECTOR_HASHERS: Dict[str, Callable] = {
    "NetworkConfigCollector": _hash_network_config,
    "SSHConfigCollector": _hash_ssh_config,
    "HostsFileCollector": _hash_hosts_file,
}


def hash_fingerprint_data(
    data: Dict[str, Any], sensitive_fields: Optional[list] = None
) -> Dict[str, Any]:
    """
    Hash sensitive fields in fingerprint data while preserving structure.

    Operates on the ``collectors`` sub-dict of a fingerprint, matching
    collector names to their corresponding hashing logic.

    Default sensitive collectors:
    - NetworkConfigCollector  (IP addresses, ARP cache, routing table, WiFi)
    - SSHConfigCollector      (known_hosts)
    - HostsFileCollector      (hosts file entries)

    Args:
        data: The fingerprint data dictionary
        sensitive_fields: Custom list of fields to hash (optional, unused -
            kept for backwards compatibility)

    Returns:
        Dictionary with sensitive fields hashed
    """
    hashed_data = data.copy()
    collectors = hashed_data.get("collectors")
    if not isinstance(collectors, dict):
        return hashed_data

    hashed_collectors = collectors.copy()
    for collector_name, hasher in _COLLECTOR_HASHERS.items():
        if collector_name in hashed_collectors:
            collector_data = hashed_collectors[collector_name]
            if isinstance(collector_data, (dict, list)):
                hashed_collectors[collector_name] = hasher(collector_data)

    hashed_data["collectors"] = hashed_collectors
    return hashed_data


class FingerprintEncryption:
    """
    Handles encryption and decryption of fingerprint data using AES-256-GCM.
    """

    def __init__(self, password: Optional[str] = None):
        """
        Initialize encryption with a password for key derivation.

        Args:
            password: Password for key derivation. Required for both
                encryption and decryption.

        Raises:
            ValueError: If password is not provided
        """
        if not password:
            raise ValueError(
                "A password is required for encryption. "
                "Without a password, encrypted data cannot be decrypted."
            )
        self.password = password
        self._key = None

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
        )
        return kdf.derive(self.password.encode("utf-8"))

    def encrypt(self, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Encrypt fingerprint data.

        Args:
            data: Dictionary to encrypt

        Returns:
            Dictionary with encrypted_data, nonce, salt, and hmac
        """
        # Generate salt and derive key
        salt = secrets.token_bytes(16)
        key = self._derive_key(salt)

        # Serialize data
        plaintext = json.dumps(data, sort_keys=True).encode("utf-8")

        # Encrypt with AES-GCM
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return {
            "encrypted_data": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "salt": base64.b64encode(salt).decode("utf-8"),
            "version": "1.0",
        }

    def decrypt(self, encrypted_data: Dict[str, str]) -> Dict[str, Any]:
        """
        Decrypt fingerprint data.

        Args:
            encrypted_data: Dictionary with encrypted_data, nonce, and salt

        Returns:
            Decrypted dictionary

        Raises:
            ValueError: If decryption fails
        """
        try:
            # Decode components
            ciphertext = base64.b64decode(encrypted_data["encrypted_data"])
            nonce = base64.b64decode(encrypted_data["nonce"])
            salt = base64.b64decode(encrypted_data["salt"])

            # Derive key
            key = self._derive_key(salt)

            # Decrypt
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


_DEFAULT_INTEGRITY_KEY = b"macos-fingerprint-integrity-v1"


def _derive_hmac_key(password: str) -> bytes:
    """Derive a dedicated HMAC key from a user password.

    Uses PBKDF2 with a fixed, distinct salt so the derived key differs
    from the encryption key (which uses a random salt).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"macos-fingerprint-hmac-salt-v1",
        iterations=100_000,
    )
    return kdf.derive(password.encode("utf-8"))


def compute_integrity_hash(
    data: Dict[str, Any], password: Optional[str] = None
) -> str:
    """
    Compute HMAC-SHA256 for integrity verification.

    When *password* is provided the HMAC key is derived from it via PBKDF2,
    making forgery infeasible without the password.  Without a password a
    fixed application-level key is used; this guards against **accidental
    corruption only** — anyone with the source code can recompute the hash.

    Args:
        data: Dictionary to hash
        password: Optional password for key derivation

    Returns:
        Hex-encoded HMAC
    """
    key = _derive_hmac_key(password) if password else _DEFAULT_INTEGRITY_KEY
    serialized = json.dumps(data, sort_keys=True).encode("utf-8")
    return hmac.new(key, serialized, hashlib.sha256).hexdigest()
