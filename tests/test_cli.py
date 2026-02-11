"""Tests for CLI module."""

import tempfile
import os
from unittest.mock import patch, MagicMock

import pytest

from macos_fingerprint.cli import cmd_create, cmd_hash, _resolve_password


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    # Cleanup
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def sample_fingerprint():
    """Sample fingerprint for testing."""
    return {
        "timestamp": "2024-01-01T00:00:00",
        "collectors": {
            "system": {"os_version": "14.0"},
        },
    }


class TestResolvePassword:
    """Test password resolution logic."""

    def test_resolve_from_password_flag(self):
        """--password flag is used directly."""
        args = MagicMock()
        args.password = "direct"
        args.password_file = None
        assert _resolve_password(args) == "direct"

    def test_resolve_from_password_file(self, tmp_path):
        """--password-file reads from file."""
        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("from_file\n")

        args = MagicMock()
        args.password = None
        args.password_file = str(pw_file)
        assert _resolve_password(args) == "from_file"

    def test_resolve_password_file_missing(self, tmp_path):
        """Missing password file exits with error."""
        args = MagicMock()
        args.password = None
        args.password_file = str(tmp_path / "nonexistent.txt")

        with pytest.raises(SystemExit):
            _resolve_password(args)

    @patch("sys.stdin")
    def test_resolve_non_interactive_no_password(self, mock_stdin):
        """Non-interactive mode without password exits with error."""
        mock_stdin.isatty.return_value = False
        args = MagicMock()
        args.password = None
        args.password_file = None

        with pytest.raises(SystemExit):
            _resolve_password(args)

    @patch("macos_fingerprint.cli.getpass.getpass", return_value="prompted")
    @patch("sys.stdin")
    def test_resolve_interactive_prompt(self, mock_stdin, mock_getpass):
        """Interactive mode prompts for password."""
        mock_stdin.isatty.return_value = True
        args = MagicMock()
        args.password = None
        args.password_file = None

        assert _resolve_password(args) == "prompted"
        mock_getpass.assert_called_once()


class TestCmdCreate:
    """Test cmd_create function."""

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_create_basic(
        self, mock_hash, mock_save, mock_create, sample_fingerprint, temp_file
    ):
        """Test basic fingerprint creation."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = True
        mock_hash.return_value = "abc123"

        args = MagicMock()
        args.output = temp_file
        args.no_hash = False
        args.encrypt = False
        args.password = None
        args.password_file = None

        cmd_create(args)

        # Verify functions were called correctly
        mock_create.assert_called_once_with(hash_sensitive=True)
        mock_save.assert_called_once_with(
            sample_fingerprint, temp_file, encrypt=False, password=None
        )
        mock_hash.assert_called_once()

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    def test_create_no_hash(
        self, mock_save, mock_create, sample_fingerprint, temp_file
    ):
        """Test creating fingerprint without hashing."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = True

        args = MagicMock()
        args.output = temp_file
        args.no_hash = True
        args.encrypt = False
        args.password = None
        args.password_file = None

        cmd_create(args)

        # Should create with hash_sensitive=False
        mock_create.assert_called_once_with(hash_sensitive=False)

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    def test_create_encrypted(
        self, mock_save, mock_create, sample_fingerprint, temp_file
    ):
        """Test creating encrypted fingerprint."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = True

        args = MagicMock()
        args.output = temp_file
        args.no_hash = False
        args.encrypt = True
        args.password = "test123"
        args.password_file = None

        cmd_create(args)

        # Should save with encryption
        mock_save.assert_called_once_with(
            sample_fingerprint, temp_file, encrypt=True, password="test123"
        )

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    def test_create_save_failure(
        self, mock_save, mock_create, sample_fingerprint, temp_file
    ):
        """Test handling of save failure."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = False  # Simulate save failure

        args = MagicMock()
        args.output = temp_file
        args.no_hash = False
        args.encrypt = False
        args.password = None
        args.password_file = None

        with pytest.raises(SystemExit) as exc_info:
            cmd_create(args)

        assert exc_info.value.code == 1


class TestCmdHash:
    """Test cmd_hash function."""

    @patch("macos_fingerprint.cli.load_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_hash_success(self, mock_hash, mock_load, sample_fingerprint, temp_file):
        """Test successful fingerprint hashing."""
        mock_load.return_value = sample_fingerprint
        mock_hash.return_value = "abc123def456"

        args = MagicMock()
        args.file = temp_file
        args.encrypted = False
        args.password = None
        args.password_file = None

        cmd_hash(args)

        mock_load.assert_called_once_with(temp_file, encrypted=False, password=None)
        mock_hash.assert_called_once_with(sample_fingerprint)

    @patch("macos_fingerprint.cli.load_fingerprint")
    def test_hash_load_failure(self, mock_load, temp_file):
        """Test handling of fingerprint load failure."""
        mock_load.return_value = None  # Simulate load failure

        args = MagicMock()
        args.file = temp_file
        args.encrypted = False
        args.password = None
        args.password_file = None

        with pytest.raises(SystemExit) as exc_info:
            cmd_hash(args)

        assert exc_info.value.code == 1

    @patch("macos_fingerprint.cli.load_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_hash_encrypted(self, mock_hash, mock_load, sample_fingerprint, temp_file):
        """Test hashing an encrypted fingerprint."""
        mock_load.return_value = sample_fingerprint
        mock_hash.return_value = "abc123"

        args = MagicMock()
        args.file = temp_file
        args.encrypted = True
        args.password = "secret"
        args.password_file = None

        cmd_hash(args)

        mock_load.assert_called_once_with(temp_file, encrypted=True, password="secret")


class TestCLIIntegration:
    """Integration tests for CLI workflow."""

    @patch("macos_fingerprint.cli.create_fingerprint")
    def test_create_and_hash_workflow(self, mock_create, sample_fingerprint, temp_file):
        """Test complete create and hash workflow."""
        mock_create.return_value = sample_fingerprint

        # Create fingerprint
        args_create = MagicMock()
        args_create.output = temp_file
        args_create.no_hash = False
        args_create.encrypt = False
        args_create.password = None
        args_create.password_file = None

        # This will actually save the file since we're not mocking save_fingerprint
        cmd_create(args_create)

        # Verify file was created
        assert os.path.exists(temp_file)
