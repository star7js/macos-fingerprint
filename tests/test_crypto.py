"""
Tests for cryptographic utilities.
"""

import pytest
from macos_fingerprint.utils.crypto import (
    hash_sensitive_value,
    hash_fingerprint_data,
    FingerprintEncryption,
    compute_integrity_hash
)


class TestHashSensitiveValue:
    """Test sensitive value hashing."""

    def test_hash_value(self):
        """Test hashing a value."""
        value = "192.168.1.1"
        hashed = hash_sensitive_value(value)

        assert hashed != value
        assert len(hashed) == 64  # SHA3-256 produces 64 hex characters

    def test_hash_same_value_twice(self):
        """Test hashing same value produces same result."""
        value = "192.168.1.1"
        hashed1 = hash_sensitive_value(value)
        hashed2 = hash_sensitive_value(value)

        assert hashed1 == hashed2

    def test_hash_empty_string(self):
        """Test hashing empty string."""
        hashed = hash_sensitive_value("")
        assert hashed == ""


class TestHashFingerprintData:
    """Test fingerprint data hashing."""

    def test_hash_network_config(self):
        """Test hashing network config data."""
        data = {
            "network_config": {
                "ip_addresses": {
                    "en0": "192.168.1.100"
                },
                "arp_cache": ["192.168.1.1 at aa:bb:cc:dd:ee:ff"]
            }
        }

        hashed_data = hash_fingerprint_data(data)

        # Verify IPs are hashed
        assert hashed_data["network_config"]["ip_addresses"]["en0"] != "192.168.1.100"
        assert len(hashed_data["network_config"]["ip_addresses"]["en0"]) == 64

        # Verify ARP cache is hashed
        assert hashed_data["network_config"]["arp_cache"][0] != data["network_config"]["arp_cache"][0]

    def test_hash_ssh_config(self):
        """Test hashing SSH config."""
        data = {
            "ssh_config": {
                "known_hosts": ["192.168.1.1 ssh-rsa AAAAB3..."]
            }
        }

        hashed_data = hash_fingerprint_data(data)

        assert hashed_data["ssh_config"]["known_hosts"][0] != data["ssh_config"]["known_hosts"][0]


class TestFingerprintEncryption:
    """Test fingerprint encryption."""

    def test_encrypt_decrypt_with_password(self):
        """Test encryption and decryption with password."""
        password = "test_password"
        data = {"test": "data", "nested": {"value": 123}}

        encryptor = FingerprintEncryption(password)
        encrypted = encryptor.encrypt(data)

        assert "encrypted_data" in encrypted
        assert "nonce" in encrypted
        assert "salt" in encrypted

        # Decrypt
        decrypted = encryptor.decrypt(encrypted)
        assert decrypted == data

    def test_decrypt_wrong_password(self):
        """Test decryption with wrong password fails."""
        data = {"test": "data"}

        encryptor1 = FingerprintEncryption("password1")
        encrypted = encryptor1.encrypt(data)

        encryptor2 = FingerprintEncryption("password2")
        with pytest.raises(ValueError):
            encryptor2.decrypt(encrypted)

    def test_encrypt_without_password(self):
        """Test encryption without password."""
        data = {"test": "data"}

        encryptor = FingerprintEncryption()
        encrypted = encryptor.encrypt(data)

        assert "encrypted_data" in encrypted

    def test_integrity_hash(self):
        """Test integrity hash computation."""
        data = {"test": "data", "value": 123}

        hash1 = compute_integrity_hash(data)
        hash2 = compute_integrity_hash(data)

        assert hash1 == hash2
        assert len(hash1) == 64

        # Different data produces different hash
        data2 = {"test": "different"}
        hash3 = compute_integrity_hash(data2)
        assert hash1 != hash3
