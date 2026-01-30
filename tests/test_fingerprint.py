"""Tests for fingerprint module."""

import json
from datetime import datetime

import pytest

from macos_fingerprint.core.fingerprint import (
    create_fingerprint,
    hash_fingerprint,
    register_all_collectors,
)
from macos_fingerprint.collectors.base import CollectorRegistry


@pytest.fixture(autouse=True)
def clean_registry():
    """Clean collector registry before each test."""
    CollectorRegistry._collectors = {}
    yield
    CollectorRegistry._collectors = {}


class TestRegisterAllCollectors:
    """Test collector registration."""

    def test_register_all_collectors(self):
        """Test that all collectors are registered."""
        register_all_collectors()
        collectors = CollectorRegistry.get_all_collectors()

        assert len(collectors) > 0
        # Should have collectors from all categories
        collector_names = [c.name for c in collectors]
        # Check for at least one from each category
        assert any("apps" in name.lower() for name in collector_names)
        assert any("system" in name.lower() for name in collector_names)
        assert any("network" in name.lower() for name in collector_names)
        assert any("security" in name.lower() for name in collector_names)
        assert any("user" in name.lower() for name in collector_names)


class TestCreateFingerprint:
    """Test create_fingerprint function."""

    def test_create_fingerprint_structure(self):
        """Test that created fingerprint has correct structure."""
        fingerprint = create_fingerprint()

        assert "timestamp" in fingerprint
        assert "collectors" in fingerprint
        assert isinstance(fingerprint["collectors"], dict)

    def test_create_fingerprint_timestamp(self):
        """Test that timestamp is valid ISO format."""
        fingerprint = create_fingerprint()

        # Should be parseable as ISO datetime
        timestamp = datetime.fromisoformat(fingerprint["timestamp"])
        assert isinstance(timestamp, datetime)

    def test_create_fingerprint_has_collectors(self):
        """Test that fingerprint includes collector data."""
        fingerprint = create_fingerprint()

        # Should have some collector results
        assert len(fingerprint["collectors"]) > 0

    def test_create_fingerprint_with_hashing(self):
        """Test fingerprint creation with sensitive field hashing."""
        fingerprint = create_fingerprint(hash_sensitive=True)

        # Fingerprint should be created
        assert fingerprint is not None
        assert "collectors" in fingerprint

    def test_create_fingerprint_without_hashing(self):
        """Test fingerprint creation without hashing."""
        fingerprint = create_fingerprint(hash_sensitive=False)

        # Fingerprint should be created
        assert fingerprint is not None
        assert "collectors" in fingerprint

    def test_create_fingerprint_collector_results(self):
        """Test that collector results are included."""
        fingerprint = create_fingerprint()

        # Each collector should return a dict
        for collector_name, result in fingerprint["collectors"].items():
            assert isinstance(result, dict)
            # Can be: error dict, data dict, or empty dict (no data collected)


class TestHashFingerprint:
    """Test hash_fingerprint function."""

    def test_hash_fingerprint_returns_string(self):
        """Test that hash returns a hex string."""
        fingerprint = {"timestamp": "2024-01-01T00:00:00", "collectors": {}}
        hash_value = hash_fingerprint(fingerprint)

        assert isinstance(hash_value, str)
        assert len(hash_value) == 64  # SHA-256 produces 64 hex chars

    def test_hash_fingerprint_deterministic(self):
        """Test that same fingerprint produces same hash."""
        fingerprint = {
            "timestamp": "2024-01-01T00:00:00",
            "collectors": {"system": {"os": "macOS 14.0"}},
        }

        hash1 = hash_fingerprint(fingerprint)
        hash2 = hash_fingerprint(fingerprint)

        assert hash1 == hash2

    def test_hash_fingerprint_different_data(self):
        """Test that different fingerprints produce different hashes."""
        fp1 = {
            "timestamp": "2024-01-01T00:00:00",
            "collectors": {"system": {"os": "macOS 14.0"}},
        }
        fp2 = {
            "timestamp": "2024-01-01T00:00:00",
            "collectors": {"system": {"os": "macOS 14.1"}},
        }

        hash1 = hash_fingerprint(fp1)
        hash2 = hash_fingerprint(fp2)

        assert hash1 != hash2

    def test_hash_fingerprint_order_independent(self):
        """Test that hash is independent of dict key order."""
        fp1 = {
            "timestamp": "2024-01-01T00:00:00",
            "collectors": {"a": 1, "b": 2},
        }
        fp2 = {
            "collectors": {"b": 2, "a": 1},
            "timestamp": "2024-01-01T00:00:00",
        }

        hash1 = hash_fingerprint(fp1)
        hash2 = hash_fingerprint(fp2)

        # Should be same due to sort_keys=True in json.dumps
        assert hash1 == hash2

    def test_hash_fingerprint_with_nested_data(self):
        """Test hashing fingerprint with nested structures."""
        fingerprint = {
            "timestamp": "2024-01-01T00:00:00",
            "collectors": {
                "system": {"os": "macOS 14.0", "apps": ["Safari", "Mail"]},
                "network": {"interfaces": {"en0": {"ip": "192.168.1.1"}}},
            },
        }

        hash_value = hash_fingerprint(fingerprint)

        assert isinstance(hash_value, str)
        assert len(hash_value) == 64


class TestIntegration:
    """Integration tests for fingerprint workflow."""

    def test_full_fingerprint_workflow(self):
        """Test complete fingerprint creation and hashing."""
        # Create fingerprint
        fingerprint = create_fingerprint(hash_sensitive=True)

        # Verify structure
        assert "timestamp" in fingerprint
        assert "collectors" in fingerprint

        # Hash it
        hash_value = hash_fingerprint(fingerprint)
        assert isinstance(hash_value, str)
        assert len(hash_value) == 64

        # Create same fingerprint again and verify hash changes (due to timestamp)
        fingerprint2 = create_fingerprint(hash_sensitive=True)
        hash_value2 = hash_fingerprint(fingerprint2)

        # Hashes should be different due to different timestamps
        assert hash_value != hash_value2
