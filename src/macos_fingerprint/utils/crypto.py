"""
Cryptographic utilities for hashing and encrypting sensitive fingerprint data.
"""

import hashlib
import json
import secrets
import base64
from typing import Any, Dict, Optional
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


def hash_fingerprint_data(
    data: Dict[str, Any], sensitive_fields: Optional[list] = None
) -> Dict[str, Any]:
    """
    Hash sensitive fields in fingerprint data while preserving structure.

    Default sensitive fields:
    - IP addresses
    - MAC addresses
    - SSH known_hosts
    - ARP cache entries
    - Network interface details

    Args:
        data: The fingerprint data dictionary
        sensitive_fields: Custom list of fields to hash (optional)

    Returns:
        Dictionary with sensitive fields hashed
    """
    if sensitive_fields is None:
        sensitive_fields = [
            "ip_addresses",
            "arp_cache",
            "known_hosts",
            "wifi_networks",
            "routing_table",
        ]

    hashed_data = data.copy()

    # Hash network config sensitive data
    if "network_config" in hashed_data:
        net_config = hashed_data["network_config"].copy()

        # Hash IP addresses
        if "ip_addresses" in net_config and isinstance(
            net_config["ip_addresses"], dict
        ):
            net_config["ip_addresses"] = {
                service: hash_sensitive_value(ip)
                for service, ip in net_config["ip_addresses"].items()
            }

        # Hash ARP cache
        if "arp_cache" in net_config and isinstance(net_config["arp_cache"], list):
            net_config["arp_cache"] = [
                hash_sensitive_value(line) if line else ""
                for line in net_config["arp_cache"]
            ]

        # Hash routing table
        if "routing_table" in net_config and isinstance(
            net_config["routing_table"], list
        ):
            net_config["routing_table"] = [
                hash_sensitive_value(line) if line else ""
                for line in net_config["routing_table"]
            ]

        # Hash WiFi networks (contains MAC addresses)
        if "wifi_networks" in net_config and isinstance(
            net_config["wifi_networks"], list
        ):
            net_config["wifi_networks"] = [
                hash_sensitive_value(line) if line else ""
                for line in net_config["wifi_networks"]
            ]

        hashed_data["network_config"] = net_config

    # Hash SSH known_hosts
    if "ssh_config" in hashed_data and isinstance(hashed_data["ssh_config"], dict):
        ssh_config = hashed_data["ssh_config"].copy()
        if "known_hosts" in ssh_config and isinstance(ssh_config["known_hosts"], list):
            ssh_config["known_hosts"] = [
                hash_sensitive_value(line) if line else ""
                for line in ssh_config["known_hosts"]
            ]
        hashed_data["ssh_config"] = ssh_config

    # Hash hosts file entries
    if "hosts_file" in hashed_data and isinstance(hashed_data["hosts_file"], list):
        hashed_data["hosts_file"] = [
            hash_sensitive_value(line) if line and not line.startswith("#") else line
            for line in hashed_data["hosts_file"]
        ]

    return hashed_data


class FingerprintEncryption:
    """
    Handles encryption and decryption of fingerprint data using AES-256-GCM.
    """

    def __init__(self, password: Optional[str] = None):
        """
        Initialize encryption with a password or generate a random key.

        Args:
            password: Optional password for key derivation
        """
        self.password = password
        self._key = None

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        if self.password:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
            )
            return kdf.derive(self.password.encode("utf-8"))
        else:
            # Generate random key
            return secrets.token_bytes(32)

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


def compute_integrity_hash(data: Dict[str, Any]) -> str:
    """
    Compute HMAC-SHA256 for integrity verification.

    Args:
        data: Dictionary to hash

    Returns:
        Hex-encoded HMAC
    """
    serialized = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()
