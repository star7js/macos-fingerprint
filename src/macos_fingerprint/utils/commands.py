"""
Safe command execution utilities with input validation.
"""

import subprocess
import os
import re
from typing import List, Optional
from pathlib import Path


def sanitize_path(path: str) -> str:
    """
    Sanitize a file path to prevent path traversal attacks.

    Args:
        path: The path to sanitize

    Returns:
        Sanitized absolute path

    Raises:
        ValueError: If path is invalid or attempts traversal
    """
    if not path:
        raise ValueError("Path cannot be empty")

    # Expand user home directory
    expanded = os.path.expanduser(path)

    # Resolve to absolute path and normalize
    resolved = os.path.abspath(expanded)

    # Check for suspicious patterns
    if '..' in path or path.startswith('/dev/') or path.startswith('/proc/'):
        raise ValueError(f"Invalid path: {path}")

    return resolved


def validate_command(command: List[str]) -> bool:
    """
    Validate a command before execution.

    Args:
        command: Command as list of strings

    Returns:
        True if valid

    Raises:
        ValueError: If command is invalid
    """
    if not command or not isinstance(command, list):
        raise ValueError("Command must be a non-empty list")

    if not all(isinstance(arg, str) for arg in command):
        raise ValueError("All command arguments must be strings")

    # Check for shell metacharacters in command arguments
    dangerous_chars = ['|', '&', ';', '>', '<', '`', '$', '(', ')']
    for arg in command:
        if any(char in arg for char in dangerous_chars):
            # Allow these in specific safe contexts (like osascript)
            if command[0] not in ['osascript']:
                raise ValueError(f"Command contains dangerous characters: {arg}")

    return True


def run_command(command: List[str], timeout: int = 30) -> Optional[str]:
    """
    Execute a command safely with proper error handling.

    Args:
        command: Command as list of strings
        timeout: Timeout in seconds (default: 30)

    Returns:
        Command output as string, or None on error
    """
    try:
        # Validate command
        validate_command(command)

        # Execute command with timeout and no shell
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
            shell=False  # NEVER use shell=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None
    except PermissionError:
        return None
    except ValueError as e:
        # Command validation failed
        print(f"Command validation error: {e}")
        return None
    except Exception:
        return None


def safe_read_file(filepath: str, max_size: int = 10 * 1024 * 1024) -> Optional[str]:
    """
    Safely read a file with size limits.

    Args:
        filepath: Path to file
        max_size: Maximum file size in bytes (default: 10MB)

    Returns:
        File contents as string, or None on error
    """
    try:
        sanitized_path = sanitize_path(filepath)

        # Check file size
        if os.path.getsize(sanitized_path) > max_size:
            print(f"File too large: {filepath}")
            return None

        with open(sanitized_path, 'r', encoding='utf-8') as f:
            return f.read()
    except (OSError, IOError, ValueError):
        return None


def safe_write_file(filepath: str, content: str, permissions: int = 0o600) -> bool:
    """
    Safely write a file with secure permissions.

    Args:
        filepath: Path to file
        content: Content to write
        permissions: File permissions (default: 0o600 - owner read/write only)

    Returns:
        True if successful, False otherwise
    """
    try:
        sanitized_path = sanitize_path(filepath)

        # Ensure parent directory exists
        parent_dir = os.path.dirname(sanitized_path)
        os.makedirs(parent_dir, exist_ok=True)

        # Write file
        with open(sanitized_path, 'w', encoding='utf-8') as f:
            f.write(content)

        # Set secure permissions
        os.chmod(sanitized_path, permissions)

        return True
    except (OSError, IOError, ValueError):
        return False


def validate_json_safe(json_string: str, max_size: int = 100 * 1024 * 1024) -> bool:
    """
    Validate JSON string is safe to parse.

    Args:
        json_string: JSON string to validate
        max_size: Maximum size in bytes (default: 100MB)

    Returns:
        True if safe to parse

    Raises:
        ValueError: If JSON is potentially unsafe
    """
    if not json_string:
        raise ValueError("JSON string is empty")

    if len(json_string) > max_size:
        raise ValueError(f"JSON string too large: {len(json_string)} bytes")

    # Check for excessive nesting (simple heuristic)
    if json_string.count('{') > 1000 or json_string.count('[') > 1000:
        raise ValueError("JSON has excessive nesting")

    return True
