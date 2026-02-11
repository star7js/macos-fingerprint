"""
Configuration file support for macOS Fingerprint.

Reads settings from ``~/.macos-fingerprint/config.toml`` (TOML format).
On Python 3.11+ the built-in ``tomllib`` is used; on 3.10 a minimal
TOML subset parser is provided so we don't require an extra dependency.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default config directory and file
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".macos-fingerprint")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.toml")

# Default configuration values
DEFAULTS: Dict[str, Any] = {
    "output": "fingerprint.json",
    "hash_sensitive": True,
    "encrypt": False,
    "parallel": False,
    "collectors": [],  # empty = all
    "exclude": [],
    "ignore_collectors": [],
}


def _parse_toml(text: str) -> Dict[str, Any]:
    """Parse TOML using tomllib (3.11+) or a minimal fallback."""
    try:
        import tomllib  # noqa: F811  — Python 3.11+

        return tomllib.loads(text)
    except ModuleNotFoundError:
        pass

    # Minimal fallback: handles key = "value", key = true/false,
    # key = 123, key = ["a", "b"], and [section] headers.
    result: Dict[str, Any] = {}
    current_section: Optional[Dict[str, Any]] = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Section header
        if line.startswith("[") and line.endswith("]"):
            section_name = line[1:-1].strip()
            result[section_name] = {}
            current_section = result[section_name]
            continue

        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        parsed_value: Any
        if value.lower() == "true":
            parsed_value = True
        elif value.lower() == "false":
            parsed_value = False
        elif value.startswith('"') and value.endswith('"'):
            parsed_value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            parsed_value = value[1:-1]
        elif value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            if not inner:
                parsed_value = []
            else:
                items = []
                for item in inner.split(","):
                    item = item.strip().strip("\"'")
                    items.append(item)
                parsed_value = items
        else:
            try:
                parsed_value = int(value)
            except ValueError:
                try:
                    parsed_value = float(value)
                except ValueError:
                    parsed_value = value

        target = current_section if current_section is not None else result
        target[key] = parsed_value

    return result


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from a TOML file.

    Args:
        path: Path to the config file. Defaults to
              ``~/.macos-fingerprint/config.toml``.

    Returns:
        Merged dict of defaults + file values. If the file does not
        exist or cannot be parsed, defaults are returned.
    """
    config_path = path or CONFIG_FILE

    merged = dict(DEFAULTS)

    if not os.path.isfile(config_path):
        return merged

    try:
        with open(config_path, "r") as f:
            raw = f.read()
        parsed = _parse_toml(raw)

        # Flatten: top-level keys override defaults directly.
        for key, value in parsed.items():
            if isinstance(value, dict):
                # Nested section — merge into top-level for simplicity.
                for sub_key, sub_value in value.items():
                    merged[sub_key] = sub_value
            else:
                merged[key] = value

        logger.debug("Loaded config from %s", config_path)
    except Exception as e:
        logger.warning("Could not parse config %s: %s", config_path, e)

    return merged


def init_config(path: Optional[str] = None) -> str:
    """Create a default config file if one doesn't exist.

    Args:
        path: Path to write. Defaults to ``~/.macos-fingerprint/config.toml``.

    Returns:
        The path of the config file.
    """
    config_path = path or CONFIG_FILE
    config_dir = os.path.dirname(config_path)

    os.makedirs(config_dir, mode=0o700, exist_ok=True)

    if os.path.exists(config_path):
        return config_path

    template = """\
# macOS Fingerprint configuration
# See: macos-fingerprint list-collectors for available collector names.

# Default output file
output = "fingerprint.json"

# Hash sensitive fields (IP addresses, SSH keys, etc.)
hash_sensitive = true

# Encrypt the output file
encrypt = false

# Run collectors in parallel for faster scans
parallel = false

# Only run these collectors (empty = all)
# collectors = ["SystemInfoCollector", "NetworkConfigCollector"]
collectors = []

# Skip these collectors
# exclude = ["BluetoothDevicesCollector", "PrintersCollector"]
exclude = []

# Collectors whose changes should be ignored in comparisons
ignore_collectors = []
"""

    try:
        with open(config_path, "w") as f:
            f.write(template)
        os.chmod(config_path, 0o600)
        logger.info("Created default config at %s", config_path)
    except OSError as e:
        logger.warning("Could not write config file: %s", e)

    return config_path


def apply_config_to_args(args, config: Dict[str, Any]) -> None:
    """Apply config values as defaults for CLI args.

    CLI flags always take precedence. Config values are only applied
    when the CLI flag was not explicitly set.
    """
    # Boolean flags — only apply if CLI left them at default (False)
    for flag in ("encrypt", "parallel"):
        if not getattr(args, flag, False) and config.get(flag, False):
            setattr(args, flag, True)

    # Output file — only if CLI used the default
    if getattr(args, "output", "fingerprint.json") == "fingerprint.json":
        cfg_output = config.get("output", "fingerprint.json")
        if cfg_output != "fingerprint.json":
            args.output = cfg_output

    # Collector lists — only if CLI didn't specify them
    if not getattr(args, "collectors", None) and config.get("collectors"):
        args.collectors = ",".join(config["collectors"])

    if not getattr(args, "exclude", None) and config.get("exclude"):
        args.exclude = ",".join(config["exclude"])

    # hash_sensitive — CLI has --no-hash (inverted)
    if not getattr(args, "no_hash", False) and not config.get("hash_sensitive", True):
        args.no_hash = True

    # ignore_collectors — only if CLI didn't specify
    if not getattr(args, "ignore_collectors", None) and config.get("ignore_collectors"):
        args.ignore_collectors = ",".join(config["ignore_collectors"])
