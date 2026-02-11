"""Tests for command execution utilities."""

import os
import tempfile

import pytest
from macos_fingerprint.utils.commands import (
    sanitize_path,
    validate_command,
    run_command,
    safe_read_file,
    safe_write_file,
    validate_json_safe,
)


class TestSanitizePath:
    """Test path sanitization."""

    def test_normal_path(self):
        """Test a normal absolute path."""
        result = sanitize_path("/tmp/test.json")
        assert result == "/tmp/test.json"

    def test_home_expansion(self):
        """Test ~ expansion."""
        result = sanitize_path("~/test.json")
        assert result.endswith("/test.json")
        assert "~" not in result

    def test_empty_path_raises(self):
        """Empty path raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            sanitize_path("")

    def test_traversal_raises(self):
        """Path traversal raises ValueError."""
        with pytest.raises(ValueError, match="Invalid path"):
            sanitize_path("/etc/../secret")

    def test_dev_path_raises(self):
        """Paths into /dev/ are rejected."""
        with pytest.raises(ValueError, match="Invalid path"):
            sanitize_path("/dev/null")

    def test_proc_path_raises(self):
        """Paths into /proc/ are rejected."""
        with pytest.raises(ValueError, match="Invalid path"):
            sanitize_path("/proc/self/environ")


class TestValidateCommand:
    """Test command validation."""

    def test_valid_command(self):
        """Test a normal command."""
        assert validate_command(["ls", "/tmp"])

    def test_empty_command_raises(self):
        """Empty command raises ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            validate_command([])

    def test_none_command_raises(self):
        """None command raises ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            validate_command(None)

    def test_non_string_args_raises(self):
        """Non-string arguments raise ValueError."""
        with pytest.raises(ValueError, match="must be strings"):
            validate_command(["ls", 123])

    def test_dangerous_pipe(self):
        """Pipe character raises ValueError."""
        with pytest.raises(ValueError, match="dangerous"):
            validate_command(["ls", "|", "grep"])

    def test_dangerous_semicolon(self):
        """Semicolon raises ValueError."""
        with pytest.raises(ValueError, match="dangerous"):
            validate_command(["ls", ";", "rm"])

    def test_osascript_exempt(self):
        """osascript is exempt from metacharacter checks."""
        assert validate_command(["osascript", "-e", "tell app \"Finder\""])


class TestRunCommand:
    """Test command execution."""

    def test_run_echo(self):
        """Test running a simple command."""
        result = run_command(["echo", "hello"])
        assert result == "hello"

    def test_run_nonexistent(self):
        """Test running a nonexistent command."""
        result = run_command(["nonexistent_command_12345"])
        assert result is None

    def test_run_failing_command(self):
        """Test running a command that fails."""
        result = run_command(["false"])
        assert result is None

    def test_run_invalid_command(self):
        """Test running an invalid (empty) command."""
        result = run_command([])
        assert result is None

    def test_run_with_timeout(self):
        """Test timeout parameter is accepted."""
        result = run_command(["echo", "fast"], timeout=5)
        assert result == "fast"


class TestSafeReadFile:
    """Test safe file reading."""

    def test_read_existing_file(self):
        """Test reading an existing file."""
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b"test content")
            os.close(fd)
            result = safe_read_file(path)
            assert result == "test content"
        finally:
            os.unlink(path)

    def test_read_nonexistent_file(self):
        """Test reading a nonexistent file."""
        result = safe_read_file("/tmp/nonexistent_file_12345.txt")
        assert result is None

    def test_read_file_too_large(self):
        """Test reading a file exceeding size limit."""
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b"x" * 100)
            os.close(fd)
            # Set max_size to 10 bytes — file is 100 bytes
            result = safe_read_file(path, max_size=10)
            assert result is None
        finally:
            os.unlink(path)


class TestSafeWriteFile:
    """Test safe file writing."""

    def test_write_file(self):
        """Test writing a file."""
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            assert safe_write_file(path, "hello")
            with open(path) as f:
                assert f.read() == "hello"
        finally:
            os.unlink(path)

    def test_write_sets_permissions(self):
        """Test that permissions are set correctly."""
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            safe_write_file(path, "secret", permissions=0o600)
            assert os.stat(path).st_mode & 0o777 == 0o600
        finally:
            os.unlink(path)

    def test_write_creates_parent_dirs(self):
        """Test that parent directories are created."""
        import shutil

        base = tempfile.mkdtemp()
        path = os.path.join(base, "sub", "dir", "file.txt")
        try:
            assert safe_write_file(path, "nested")
            with open(path) as f:
                assert f.read() == "nested"
        finally:
            shutil.rmtree(base)


class TestValidateJsonSafe:
    """Test JSON safety validation."""

    def test_valid_json(self):
        """Test valid JSON string."""
        assert validate_json_safe('{"key": "value"}')

    def test_empty_json_raises(self):
        """Empty JSON raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            validate_json_safe("")

    def test_oversized_json_raises(self):
        """Oversized JSON raises ValueError."""
        with pytest.raises(ValueError, match="too large"):
            validate_json_safe("x" * 200, max_size=100)

    def test_excessive_nesting_raises(self):
        """Excessive nesting raises ValueError."""
        deeply_nested = "{" * 1001 + "}" * 1001
        with pytest.raises(ValueError, match="excessive"):
            validate_json_safe(deeply_nested)
