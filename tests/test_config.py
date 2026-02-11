"""Tests for configuration file support."""

import os
import tempfile

import pytest

from macos_fingerprint.utils.config import (
    _parse_toml,
    load_config,
    init_config,
    apply_config_to_args,
    DEFAULTS,
)


class TestParseToml:
    """Test the minimal TOML parser."""

    def test_basic_string(self):
        result = _parse_toml('key = "value"')
        assert result == {"key": "value"}

    def test_single_quoted_string(self):
        result = _parse_toml("key = 'value'")
        assert result == {"key": "value"}

    def test_boolean_true(self):
        result = _parse_toml("flag = true")
        assert result == {"flag": True}

    def test_boolean_false(self):
        result = _parse_toml("flag = false")
        assert result == {"flag": False}

    def test_integer(self):
        result = _parse_toml("count = 42")
        assert result == {"count": 42}

    def test_empty_array(self):
        result = _parse_toml("items = []")
        assert result == {"items": []}

    def test_string_array(self):
        result = _parse_toml('items = ["a", "b", "c"]')
        assert result == {"items": ["a", "b", "c"]}

    def test_section(self):
        text = """
[section]
key = "value"
"""
        result = _parse_toml(text)
        assert result == {"section": {"key": "value"}}

    def test_comments_ignored(self):
        text = """
# Comment
key = "value"
"""
        result = _parse_toml(text)
        assert result == {"key": "value"}

    def test_empty_input(self):
        assert _parse_toml("") == {}

    def test_mixed(self):
        text = """
output = "fp.json"
parallel = true
collectors = ["A", "B"]
"""
        result = _parse_toml(text)
        assert result["output"] == "fp.json"
        assert result["parallel"] is True
        assert result["collectors"] == ["A", "B"]


class TestLoadConfig:
    """Test config loading."""

    def test_load_missing_file_returns_defaults(self):
        result = load_config("/tmp/nonexistent_config_12345.toml")
        assert result == DEFAULTS

    def test_load_valid_config(self, tmp_path):
        cfg = tmp_path / "config.toml"
        cfg.write_text('output = "custom.json"\nparallel = true\n')

        result = load_config(str(cfg))
        assert result["output"] == "custom.json"
        assert result["parallel"] is True
        # Defaults preserved for unset keys
        assert result["hash_sensitive"] is True

    def test_load_with_section(self, tmp_path):
        cfg = tmp_path / "config.toml"
        cfg.write_text('[scan]\nparallel = true\n')

        result = load_config(str(cfg))
        # Section values are flattened
        assert result["parallel"] is True

    def test_load_invalid_toml_returns_defaults(self, tmp_path):
        cfg = tmp_path / "config.toml"
        cfg.write_text("\x00\x01\x02")  # binary garbage

        result = load_config(str(cfg))
        # Should fall back to defaults without crashing
        assert "output" in result


class TestInitConfig:
    """Test config file creation."""

    def test_init_creates_file(self, tmp_path):
        path = str(tmp_path / "sub" / "config.toml")
        result = init_config(path)
        assert result == path
        assert os.path.isfile(path)

    def test_init_does_not_overwrite(self, tmp_path):
        path = str(tmp_path / "config.toml")
        with open(path, "w") as f:
            f.write("existing")

        init_config(path)
        with open(path) as f:
            assert f.read() == "existing"

    def test_init_file_contains_template_keys(self, tmp_path):
        path = str(tmp_path / "config.toml")
        init_config(path)
        with open(path) as f:
            content = f.read()
        assert "output" in content
        assert "parallel" in content
        assert "collectors" in content


class TestApplyConfigToArgs:
    """Test applying config to CLI args."""

    def _make_args(self, **kwargs):
        """Create a simple namespace-like object."""
        from unittest.mock import MagicMock
        args = MagicMock()
        defaults = {
            "output": "fingerprint.json",
            "no_hash": False,
            "encrypt": False,
            "parallel": False,
            "collectors": None,
            "exclude": None,
            "ignore_collectors": None,
        }
        defaults.update(kwargs)
        for k, v in defaults.items():
            setattr(args, k, v)
        return args

    def test_parallel_from_config(self):
        args = self._make_args()
        apply_config_to_args(args, {"parallel": True})
        assert args.parallel is True

    def test_cli_flag_overrides_config(self):
        args = self._make_args(parallel=True)
        apply_config_to_args(args, {"parallel": False})
        # CLI said True, should stay True
        assert args.parallel is True

    def test_output_from_config(self):
        args = self._make_args()
        apply_config_to_args(args, {"output": "custom.json"})
        assert args.output == "custom.json"

    def test_output_cli_overrides(self):
        args = self._make_args(output="mine.json")
        apply_config_to_args(args, {"output": "custom.json"})
        assert args.output == "mine.json"

    def test_collectors_from_config(self):
        args = self._make_args()
        apply_config_to_args(args, {"collectors": ["A", "B"]})
        assert args.collectors == "A,B"

    def test_exclude_from_config(self):
        args = self._make_args()
        apply_config_to_args(args, {"exclude": ["X"]})
        assert args.exclude == "X"

    def test_no_hash_from_config(self):
        args = self._make_args()
        apply_config_to_args(args, {"hash_sensitive": False})
        assert args.no_hash is True

    def test_ignore_collectors_from_config(self):
        args = self._make_args()
        apply_config_to_args(args, {"ignore_collectors": ["A", "B"]})
        assert args.ignore_collectors == "A,B"
