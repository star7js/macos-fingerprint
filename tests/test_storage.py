"""Tests for storage module."""

import json
import os
import tempfile

import pytest

from macos_fingerprint.core.storage import (
    save_fingerprint,
    load_fingerprint,
    export_fingerprint,
)


@pytest.fixture
def sample_fingerprint():
    """Sample fingerprint data for testing."""
    return {
        "timestamp": "2024-01-01T00:00:00",
        "collectors": {
            "system": {"os_version": "14.0", "hostname": "test-mac"},
            "network": {"interfaces": ["en0", "en1"]},
        },
    }


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    # Cleanup
    if os.path.exists(path):
        os.remove(path)


class TestSaveFingerprint:
    """Test save_fingerprint function."""

    def test_save_unencrypted(self, sample_fingerprint, temp_file):
        """Test saving unencrypted fingerprint."""
        result = save_fingerprint(sample_fingerprint, temp_file)
        assert result is True
        assert os.path.exists(temp_file)

        # Verify file has correct permissions (0600)
        stat_info = os.stat(temp_file)
        assert stat_info.st_mode & 0o777 == 0o600

    def test_save_with_integrity_hash(self, sample_fingerprint, temp_file):
        """Test that saved fingerprint includes integrity hash."""
        save_fingerprint(sample_fingerprint, temp_file)

        with open(temp_file, "r") as f:
            data = json.load(f)

        assert "_integrity_hash" in data
        assert isinstance(data["_integrity_hash"], str)

    def test_save_encrypted(self, sample_fingerprint, temp_file):
        """Test saving encrypted fingerprint."""
        result = save_fingerprint(
            sample_fingerprint, temp_file, encrypt=True, password="test123"
        )
        assert result is True
        assert os.path.exists(temp_file)

        # Verify it's encrypted (contains encrypted_data)
        with open(temp_file, "r") as f:
            data = json.load(f)

        assert "encrypted_data" in data
        assert "salt" in data
        assert "nonce" in data


class TestLoadFingerprint:
    """Test load_fingerprint function."""

    def test_load_unencrypted(self, sample_fingerprint, temp_file):
        """Test loading unencrypted fingerprint."""
        save_fingerprint(sample_fingerprint, temp_file)
        loaded = load_fingerprint(temp_file)

        assert loaded is not None
        assert loaded["timestamp"] == sample_fingerprint["timestamp"]
        assert loaded["collectors"] == sample_fingerprint["collectors"]
        assert "_integrity_hash" not in loaded  # Should be removed after verification

    def test_load_encrypted(self, sample_fingerprint, temp_file):
        """Test loading encrypted fingerprint."""
        password = "test123"
        save_fingerprint(sample_fingerprint, temp_file, encrypt=True, password=password)
        loaded = load_fingerprint(temp_file, encrypted=True, password=password)

        assert loaded is not None
        assert loaded["timestamp"] == sample_fingerprint["timestamp"]
        assert loaded["collectors"] == sample_fingerprint["collectors"]

    def test_load_encrypted_wrong_password(self, sample_fingerprint, temp_file):
        """Test loading encrypted fingerprint with wrong password."""
        save_fingerprint(
            sample_fingerprint, temp_file, encrypt=True, password="correct"
        )
        loaded = load_fingerprint(temp_file, encrypted=True, password="wrong")

        assert loaded is None

    def test_load_nonexistent_file(self):
        """Test loading non-existent file."""
        loaded = load_fingerprint("/nonexistent/file.json")
        assert loaded is None

    def test_load_invalid_json(self, temp_file):
        """Test loading file with invalid JSON."""
        with open(temp_file, "w") as f:
            f.write("not valid json{")

        loaded = load_fingerprint(temp_file)
        assert loaded is None

    def test_load_with_corrupted_hash(self, sample_fingerprint, temp_file):
        """Test loading fingerprint with corrupted integrity hash."""
        save_fingerprint(sample_fingerprint, temp_file)

        # Corrupt the hash
        with open(temp_file, "r") as f:
            data = json.load(f)
        data["_integrity_hash"] = "corrupted_hash"
        with open(temp_file, "w") as f:
            json.dump(data, f)

        # Should still load but print warning (captured in output)
        loaded = load_fingerprint(temp_file)
        assert loaded is not None


class TestExportFingerprint:
    """Test export_fingerprint function."""

    def test_export(self, sample_fingerprint, temp_file):
        """Test export_fingerprint is a wrapper for save_fingerprint."""
        result = export_fingerprint(sample_fingerprint, temp_file)
        assert result is True

        # Verify it's saved unencrypted with integrity hash
        with open(temp_file, "r") as f:
            data = json.load(f)

        assert "_integrity_hash" in data


class TestRoundTrip:
    """Test save and load round trips."""

    def test_unencrypted_roundtrip(self, sample_fingerprint, temp_file):
        """Test saving and loading preserves data."""
        save_fingerprint(sample_fingerprint, temp_file)
        loaded = load_fingerprint(temp_file)

        assert loaded == sample_fingerprint

    def test_encrypted_roundtrip(self, sample_fingerprint, temp_file):
        """Test encrypted save and load preserves data."""
        password = "secure_password_123"
        save_fingerprint(sample_fingerprint, temp_file, encrypt=True, password=password)
        loaded = load_fingerprint(temp_file, encrypted=True, password=password)

        assert loaded == sample_fingerprint
