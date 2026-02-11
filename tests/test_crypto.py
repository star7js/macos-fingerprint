"""
Tests for cryptographic utilities.
"""

import pytest
from macos_fingerprint.utils.crypto import (
    hash_sensitive_value,
    hash_fingerprint_data,
    FingerprintEncryption,
    compute_integrity_hash,
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

    def test_hash_different_values(self):
        """Test that different values produce different hashes."""
        h1 = hash_sensitive_value("192.168.1.1")
        h2 = hash_sensitive_value("192.168.1.2")
        assert h1 != h2


class TestHashFingerprintData:
    """Test fingerprint data hashing."""

    def test_hash_network_config(self):
        """Test hashing network config data nested under collectors."""
        data = {
            "collectors": {
                "NetworkConfigCollector": {
                    "ip_addresses": {"en0": "192.168.1.100"},
                    "arp_cache": ["192.168.1.1 at aa:bb:cc:dd:ee:ff"],
                }
            }
        }

        hashed_data = hash_fingerprint_data(data)
        net = hashed_data["collectors"]["NetworkConfigCollector"]

        # Verify IPs are hashed
        assert net["ip_addresses"]["en0"] != "192.168.1.100"
        assert len(net["ip_addresses"]["en0"]) == 64

        # Verify ARP cache is hashed
        assert net["arp_cache"][0] != "192.168.1.1 at aa:bb:cc:dd:ee:ff"

    def test_hash_ssh_config(self):
        """Test hashing SSH config nested under collectors."""
        data = {
            "collectors": {
                "SSHConfigCollector": {"known_hosts": ["192.168.1.1 ssh-rsa AAAAB3..."]}
            }
        }

        hashed_data = hash_fingerprint_data(data)

        assert (
            hashed_data["collectors"]["SSHConfigCollector"]["known_hosts"][0]
            != "192.168.1.1 ssh-rsa AAAAB3..."
        )

    def test_hash_hosts_file(self):
        """Test hashing hosts file entries nested under collectors."""
        data = {
            "collectors": {
                "HostsFileCollector": [
                    "127.0.0.1 localhost",
                    "# comment line",
                ]
            }
        }

        hashed_data = hash_fingerprint_data(data)
        hosts = hashed_data["collectors"]["HostsFileCollector"]

        # Non-comment line should be hashed
        assert hosts[0] != "127.0.0.1 localhost"
        # Comment line should be preserved
        assert hosts[1] == "# comment line"

    def test_hash_without_collectors_key(self):
        """Test that data without a collectors key is returned unchanged."""
        data = {"timestamp": "2024-01-01"}
        assert hash_fingerprint_data(data) == data

    def test_hash_preserves_non_sensitive_collectors(self):
        """Test that collectors not in the sensitive list are untouched."""
        data = {
            "collectors": {
                "InstalledAppsCollector": {"system": ["App1"]},
            }
        }
        hashed = hash_fingerprint_data(data)
        assert hashed["collectors"]["InstalledAppsCollector"] == {"system": ["App1"]}

    def test_hash_does_not_modify_original(self):
        """Test that original data is not modified in-place."""
        data = {
            "collectors": {
                "NetworkConfigCollector": {
                    "ip_addresses": {"en0": "10.0.0.1"},
                }
            }
        }
        hash_fingerprint_data(data)
        assert data["collectors"]["NetworkConfigCollector"]["ip_addresses"]["en0"] == "10.0.0.1"

    def test_hash_wifi_networks(self):
        """Test that wifi_networks in NetworkConfigCollector are hashed."""
        data = {
            "collectors": {
                "NetworkConfigCollector": {
                    "wifi_networks": ["MyHomeWiFi"],
                }
            }
        }
        hashed = hash_fingerprint_data(data)
        assert hashed["collectors"]["NetworkConfigCollector"]["wifi_networks"][0] != "MyHomeWiFi"

    def test_hash_routing_table(self):
        """Test that routing_table in NetworkConfigCollector is hashed."""
        data = {
            "collectors": {
                "NetworkConfigCollector": {
                    "routing_table": ["default 192.168.1.1 UGScg en0"],
                }
            }
        }
        hashed = hash_fingerprint_data(data)
        assert hashed["collectors"]["NetworkConfigCollector"]["routing_table"][0] != "default 192.168.1.1 UGScg en0"


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

    def test_encrypt_without_password_raises(self):
        """Test that encryption without password raises ValueError."""
        with pytest.raises(ValueError, match="password is required"):
            FingerprintEncryption()

    def test_encrypt_empty_password_raises(self):
        """Test that empty string password raises ValueError."""
        with pytest.raises(ValueError, match="password is required"):
            FingerprintEncryption("")

    def test_encrypted_data_has_version(self):
        """Test that encrypted output includes version field."""
        enc = FingerprintEncryption("pw")
        result = enc.encrypt({"k": "v"})
        assert result["version"] == "1.0"


class TestIntegrityHash:
    """Test HMAC integrity hash."""

    def test_integrity_hash_deterministic(self):
        """Test integrity hash computation is deterministic."""
        data = {"test": "data", "value": 123}

        hash1 = compute_integrity_hash(data)
        hash2 = compute_integrity_hash(data)

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_integrity_hash_different_data(self):
        """Different data produces different hash."""
        data1 = {"test": "data"}
        data2 = {"test": "different"}
        assert compute_integrity_hash(data1) != compute_integrity_hash(data2)

    def test_integrity_hash_with_password(self):
        """Password-derived HMAC key differs from default key."""
        data = {"key": "value"}
        hash_no_pw = compute_integrity_hash(data)
        hash_with_pw = compute_integrity_hash(data, password="my_secret")

        # Different keys produce different hashes
        assert hash_no_pw != hash_with_pw
        assert len(hash_with_pw) == 64

    def test_integrity_hash_password_deterministic(self):
        """Same password produces same hash."""
        data = {"key": "value"}
        h1 = compute_integrity_hash(data, password="pw123")
        h2 = compute_integrity_hash(data, password="pw123")
        assert h1 == h2

    def test_integrity_hash_different_passwords(self):
        """Different passwords produce different hashes."""
        data = {"key": "value"}
        h1 = compute_integrity_hash(data, password="alpha")
        h2 = compute_integrity_hash(data, password="beta")
        assert h1 != h2
