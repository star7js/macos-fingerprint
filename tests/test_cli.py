"""Tests for CLI module."""

import json
import tempfile
import os
from unittest.mock import patch, MagicMock

import pytest

from macos_fingerprint.cli import (
    cmd_create,
    cmd_hash,
    cmd_list_collectors,
    cmd_init,
    _resolve_password,
    _parse_collector_names,
    _collector_kwargs,
    _is_json_mode,
)


def _make_args(**overrides):
    """Build a minimal args namespace for CLI commands.

    Defaults are set so that MagicMock auto-attributes don't interfere.
    """
    defaults = {
        "output": "/tmp/test.json",
        "no_hash": False,
        "encrypt": False,
        "password": None,
        "password_file": None,
        "collectors": None,
        "exclude": None,
        "parallel": False,
        "json": False,
        "encrypted": False,
        "ignore_collectors": None,
    }
    defaults.update(overrides)
    args = MagicMock()
    for k, v in defaults.items():
        setattr(args, k, v)
    return args


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
        args = _make_args(password="direct")
        assert _resolve_password(args) == "direct"

    def test_resolve_from_password_file(self, tmp_path):
        """--password-file reads from file."""
        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("from_file\n")

        args = _make_args(password=None, password_file=str(pw_file))
        assert _resolve_password(args) == "from_file"

    def test_resolve_password_file_missing(self, tmp_path):
        """Missing password file exits with error."""
        args = _make_args(password=None, password_file=str(tmp_path / "nonexistent.txt"))

        with pytest.raises(SystemExit):
            _resolve_password(args)

    @patch("sys.stdin")
    def test_resolve_non_interactive_no_password(self, mock_stdin):
        """Non-interactive mode without password exits with error."""
        mock_stdin.isatty.return_value = False
        args = _make_args(password=None, password_file=None)

        with pytest.raises(SystemExit):
            _resolve_password(args)

    @patch("macos_fingerprint.cli.getpass.getpass", return_value="prompted")
    @patch("sys.stdin")
    def test_resolve_interactive_prompt(self, mock_stdin, mock_getpass):
        """Interactive mode prompts for password."""
        mock_stdin.isatty.return_value = True
        args = _make_args(password=None, password_file=None)

        assert _resolve_password(args) == "prompted"
        mock_getpass.assert_called_once()


class TestHelpers:
    """Test CLI helper functions."""

    def test_parse_collector_names(self):
        assert _parse_collector_names("A, B ,C") == ["A", "B", "C"]

    def test_parse_collector_names_empty(self):
        assert _parse_collector_names("") == []

    def test_collector_kwargs_none(self):
        args = _make_args()
        assert _collector_kwargs(args) == {}

    def test_collector_kwargs_with_collectors(self):
        args = _make_args(collectors="A,B", parallel=True)
        kw = _collector_kwargs(args)
        assert kw["collectors"] == ["A", "B"]
        assert kw["parallel"] is True

    def test_collector_kwargs_with_exclude(self):
        args = _make_args(exclude="X")
        kw = _collector_kwargs(args)
        assert kw["exclude"] == ["X"]

    def test_is_json_mode_false(self):
        args = _make_args(json=False)
        assert _is_json_mode(args) is False

    def test_is_json_mode_true(self):
        args = _make_args(json=True)
        assert _is_json_mode(args) is True


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

        args = _make_args(output=temp_file)
        cmd_create(args)

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

        args = _make_args(output=temp_file, no_hash=True)
        cmd_create(args)

        mock_create.assert_called_once_with(hash_sensitive=False)

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    def test_create_encrypted(
        self, mock_save, mock_create, sample_fingerprint, temp_file
    ):
        """Test creating encrypted fingerprint."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = True

        args = _make_args(output=temp_file, encrypt=True, password="test123")
        cmd_create(args)

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
        mock_save.return_value = False

        args = _make_args(output=temp_file)
        with pytest.raises(SystemExit) as exc_info:
            cmd_create(args)

        assert exc_info.value.code == 1

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_create_with_collectors_filter(
        self, mock_hash, mock_save, mock_create, sample_fingerprint, temp_file
    ):
        """Test --collectors flag passes through."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = True
        mock_hash.return_value = "abc"

        args = _make_args(output=temp_file, collectors="A,B")
        cmd_create(args)

        mock_create.assert_called_once_with(
            hash_sensitive=True, collectors=["A", "B"]
        )

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_create_with_exclude(
        self, mock_hash, mock_save, mock_create, sample_fingerprint, temp_file
    ):
        """Test --exclude flag passes through."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = True
        mock_hash.return_value = "abc"

        args = _make_args(output=temp_file, exclude="X")
        cmd_create(args)

        mock_create.assert_called_once_with(
            hash_sensitive=True, exclude=["X"]
        )

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_create_parallel(
        self, mock_hash, mock_save, mock_create, sample_fingerprint, temp_file
    ):
        """Test --parallel flag passes through."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = True
        mock_hash.return_value = "abc"

        args = _make_args(output=temp_file, parallel=True)
        cmd_create(args)

        mock_create.assert_called_once_with(hash_sensitive=True, parallel=True)

    @patch("macos_fingerprint.cli.create_fingerprint")
    @patch("macos_fingerprint.cli.save_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_create_json_output(
        self, mock_hash, mock_save, mock_create, sample_fingerprint, temp_file, capsys
    ):
        """Test --json mode outputs JSON."""
        mock_create.return_value = sample_fingerprint
        mock_save.return_value = True
        mock_hash.return_value = "abc123"

        args = _make_args(output=temp_file, json=True)
        cmd_create(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["hash"] == "abc123"


class TestCmdHash:
    """Test cmd_hash function."""

    @patch("macos_fingerprint.cli.load_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_hash_success(self, mock_hash, mock_load, sample_fingerprint, temp_file):
        """Test successful fingerprint hashing."""
        mock_load.return_value = sample_fingerprint
        mock_hash.return_value = "abc123def456"

        args = _make_args(file=temp_file)
        cmd_hash(args)

        mock_load.assert_called_once_with(temp_file, encrypted=False, password=None)
        mock_hash.assert_called_once_with(sample_fingerprint)

    @patch("macos_fingerprint.cli.load_fingerprint")
    def test_hash_load_failure(self, mock_load, temp_file):
        """Test handling of fingerprint load failure."""
        mock_load.return_value = None

        args = _make_args(file=temp_file)
        with pytest.raises(SystemExit) as exc_info:
            cmd_hash(args)

        assert exc_info.value.code == 1

    @patch("macos_fingerprint.cli.load_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_hash_encrypted(self, mock_hash, mock_load, sample_fingerprint, temp_file):
        """Test hashing an encrypted fingerprint."""
        mock_load.return_value = sample_fingerprint
        mock_hash.return_value = "abc123"

        args = _make_args(file=temp_file, encrypted=True, password="secret")
        cmd_hash(args)

        mock_load.assert_called_once_with(temp_file, encrypted=True, password="secret")

    @patch("macos_fingerprint.cli.load_fingerprint")
    @patch("macos_fingerprint.cli.hash_fingerprint")
    def test_hash_json_output(self, mock_hash, mock_load, sample_fingerprint, temp_file, capsys):
        """Test --json mode for hash command."""
        mock_load.return_value = sample_fingerprint
        mock_hash.return_value = "abc123"

        args = _make_args(file=temp_file, json=True)
        cmd_hash(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["hash"] == "abc123"


class TestCmdListCollectors:
    """Test list-collectors command."""

    def test_list_collectors_text(self, capsys):
        """Test text output mode."""
        args = _make_args(json=False)
        cmd_list_collectors(args)
        captured = capsys.readouterr()
        assert "InstalledAppsCollector" in captured.out

    def test_list_collectors_json(self, capsys):
        """Test JSON output mode."""
        args = _make_args(json=True)
        cmd_list_collectors(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "InstalledAppsCollector" in data["collectors"]


class TestCmdInit:
    """Test init command."""

    def test_init_creates_config(self, tmp_path, capsys):
        """Test that init creates a config file."""
        config_path = str(tmp_path / "config.toml")
        with patch("macos_fingerprint.cli.init_config", return_value=config_path):
            args = _make_args(json=False)
            cmd_init(args)
        captured = capsys.readouterr()
        assert config_path in captured.out

    def test_init_json_output(self, tmp_path, capsys):
        """Test init with --json."""
        config_path = str(tmp_path / "config.toml")
        with patch("macos_fingerprint.cli.init_config", return_value=config_path):
            args = _make_args(json=True)
            cmd_init(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["config_path"] == config_path


class TestCLIIntegration:
    """Integration tests for CLI workflow."""

    @patch("macos_fingerprint.cli.create_fingerprint")
    def test_create_and_hash_workflow(self, mock_create, sample_fingerprint, temp_file):
        """Test complete create and hash workflow."""
        mock_create.return_value = sample_fingerprint

        args = _make_args(output=temp_file)
        cmd_create(args)

        assert os.path.exists(temp_file)
