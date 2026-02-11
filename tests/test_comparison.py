"""
Tests for fingerprint comparison.
"""

import json
import os
import tempfile

from macos_fingerprint.core.comparison import (
    compare_lists,
    compare_dicts,
    compare_fingerprints,
    export_comparison_html,
    export_comparison_json,
    ChangeSeverity,
    classify_severity,
    ChangeType,
)


class TestCompareLists:
    """Test list comparison."""

    def test_compare_identical_lists(self):
        """Test comparing identical lists."""
        list1 = ["a", "b", "c"]
        list2 = ["a", "b", "c"]

        result = compare_lists(list1, list2)

        assert result["added"] == []
        assert result["removed"] == []

    def test_compare_with_additions(self):
        """Test comparing lists with additions."""
        baseline = ["a", "b"]
        current = ["a", "b", "c"]

        result = compare_lists(baseline, current)

        assert "c" in result["added"]
        assert result["removed"] == []

    def test_compare_with_removals(self):
        """Test comparing lists with removals."""
        baseline = ["a", "b", "c"]
        current = ["a", "b"]

        result = compare_lists(baseline, current)

        assert result["added"] == []
        assert "c" in result["removed"]

    def test_compare_empty_lists(self):
        """Test comparing empty lists."""
        result = compare_lists([], [])
        assert result["added"] == []
        assert result["removed"] == []

    def test_compare_none_inputs(self):
        """Test comparing None inputs (treated as empty)."""
        result = compare_lists(None, None)
        assert result["added"] == []
        assert result["removed"] == []

    def test_compare_preserves_duplicates(self):
        """Test that duplicate entries are counted correctly."""
        baseline = ["a", "a", "b"]
        current = ["a", "b"]

        result = compare_lists(baseline, current)

        # One "a" was removed
        assert result["removed"] == ["a"]
        assert result["added"] == []

    def test_compare_duplicate_additions(self):
        """Test that added duplicates are counted."""
        baseline = ["a"]
        current = ["a", "a", "a"]

        result = compare_lists(baseline, current)

        assert result["added"] == ["a", "a"]
        assert result["removed"] == []

    def test_compare_mixed_duplicates(self):
        """Test mixed duplicate changes."""
        baseline = ["x", "x", "y"]
        current = ["x", "y", "y"]

        result = compare_lists(baseline, current)

        assert result["added"] == ["y"]
        assert result["removed"] == ["x"]


class TestCompareDicts:
    """Test dictionary comparison."""

    def test_compare_identical_dicts(self):
        """Test comparing identical dictionaries."""
        dict1 = {"a": 1, "b": 2}
        dict2 = {"a": 1, "b": 2}

        result = compare_dicts(dict1, dict2)

        assert result == {}

    def test_compare_with_modified_value(self):
        """Test comparing dicts with modified value."""
        baseline = {"a": 1, "b": 2}
        current = {"a": 1, "b": 3}

        result = compare_dicts(baseline, current)

        assert "b" in result
        assert result["b"]["type"] == "modified"
        assert result["b"]["baseline"] == 2
        assert result["b"]["current"] == 3

    def test_compare_with_added_key(self):
        """Test comparing dicts with added key."""
        baseline = {"a": 1}
        current = {"a": 1, "b": 2}

        result = compare_dicts(baseline, current)

        assert "b" in result
        assert result["b"]["type"] == "added"

    def test_compare_with_removed_key(self):
        """Test comparing dicts with removed key."""
        baseline = {"a": 1, "b": 2}
        current = {"a": 1}

        result = compare_dicts(baseline, current)

        assert "b" in result
        assert result["b"]["type"] == "removed"

    def test_compare_nested_dicts(self):
        """Test comparing nested dictionaries."""
        baseline = {"outer": {"inner": 1}}
        current = {"outer": {"inner": 2}}

        result = compare_dicts(baseline, current)

        assert "outer" in result
        assert result["outer"]["type"] == "modified"

    def test_compare_nested_lists(self):
        """Test comparing dicts containing lists."""
        baseline = {"items": ["a", "b"]}
        current = {"items": ["a", "b", "c"]}

        result = compare_dicts(baseline, current)

        assert "items" in result
        assert result["items"]["type"] == "modified"
        assert "c" in result["items"]["added"]


class TestClassifySeverity:
    """Test severity classification."""

    def test_critical_collector(self):
        """Test critical severity for security collectors."""
        severity = classify_severity("SecuritySettingsCollector", ChangeType.MODIFIED)
        assert severity == ChangeSeverity.CRITICAL

    def test_high_collector(self):
        """Test high severity for system collectors."""
        severity = classify_severity("KernelExtensionsCollector", ChangeType.MODIFIED)
        assert severity == ChangeSeverity.HIGH

    def test_medium_removal(self):
        """Test medium severity for removals."""
        severity = classify_severity("InstalledAppsCollector", ChangeType.REMOVED)
        assert severity == ChangeSeverity.MEDIUM

    def test_low_collector(self):
        """Test low severity for minor changes."""
        severity = classify_severity("PrintersCollector", ChangeType.ADDED)
        assert severity == ChangeSeverity.LOW

    def test_all_critical_collectors(self):
        """Verify all critical collectors are classified correctly."""
        for name in ["SecuritySettingsCollector", "GatekeeperCollector", "SSHConfigCollector"]:
            assert classify_severity(name, ChangeType.MODIFIED) == ChangeSeverity.CRITICAL

    def test_all_high_collectors(self):
        """Verify all high-severity collectors are classified correctly."""
        for name in [
            "KernelExtensionsCollector",
            "LaunchAgentsCollector",
            "UserAccountsCollector",
            "NetworkConfigCollector",
        ]:
            assert classify_severity(name, ChangeType.MODIFIED) == ChangeSeverity.HIGH


class TestCompareFingerprints:
    """Test full fingerprint comparison."""

    def test_compare_identical_fingerprints(self):
        """Test comparing identical fingerprints."""
        fingerprint = {
            "timestamp": "2026-01-01T00:00:00",
            "collectors": {"InstalledAppsCollector": {"system": ["App1", "App2"]}},
        }

        result = compare_fingerprints(fingerprint, fingerprint)

        assert result["summary"]["total_changes"] == 0

    def test_compare_with_changes(self):
        """Test comparing fingerprints with changes."""
        baseline = {
            "timestamp": "2026-01-01T00:00:00",
            "collectors": {"InstalledAppsCollector": {"system": ["App1", "App2"]}},
        }

        current = {
            "timestamp": "2026-01-02T00:00:00",
            "collectors": {
                "InstalledAppsCollector": {"system": ["App1", "App2", "App3"]}
            },
        }

        result = compare_fingerprints(baseline, current)

        assert result["summary"]["total_changes"] > 0
        assert "InstalledAppsCollector" in result["changes"]

    def test_compare_collector_added(self):
        """Test detection of a newly added collector."""
        baseline = {"timestamp": "t1", "collectors": {}}
        current = {
            "timestamp": "t2",
            "collectors": {"NewCollector": {"data": 1}},
        }

        result = compare_fingerprints(baseline, current)
        assert result["summary"]["total_changes"] == 1
        assert result["changes"]["NewCollector"]["type"] == "collector_added"

    def test_compare_collector_removed(self):
        """Test detection of a removed collector."""
        baseline = {
            "timestamp": "t1",
            "collectors": {"OldCollector": {"data": 1}},
        }
        current = {"timestamp": "t2", "collectors": {}}

        result = compare_fingerprints(baseline, current)
        assert result["summary"]["total_changes"] == 1
        assert result["changes"]["OldCollector"]["type"] == "collector_removed"

    def test_compare_timestamps_recorded(self):
        """Test that baseline and current timestamps are recorded."""
        fp = {"timestamp": "2026-06-01T00:00:00", "collectors": {}}
        result = compare_fingerprints(fp, fp)
        assert result["baseline_timestamp"] == "2026-06-01T00:00:00"
        assert result["current_timestamp"] == "2026-06-01T00:00:00"


class TestExport:
    """Test export functions."""

    def test_export_json(self):
        """Test exporting comparison as JSON."""
        differences = {
            "timestamp": "2026-01-01T00:00:00",
            "baseline_timestamp": "t1",
            "current_timestamp": "t2",
            "summary": {"total_changes": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "changes": {},
        }
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            assert export_comparison_json(differences, path)
            with open(path) as f:
                loaded = json.load(f)
            assert loaded["summary"]["total_changes"] == 0
        finally:
            os.unlink(path)

    def test_export_html(self):
        """Test exporting comparison as HTML."""
        differences = {
            "timestamp": "2026-01-01T00:00:00",
            "baseline_timestamp": "t1",
            "current_timestamp": "t2",
            "summary": {"total_changes": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
            "changes": {
                "SecuritySettingsCollector": {
                    "severity": "critical",
                    "type": "modified",
                    "changes": {"firewall": {"type": "modified", "baseline": "1", "current": "0"}},
                }
            },
        }
        fd, path = tempfile.mkstemp(suffix=".html")
        os.close(fd)
        try:
            assert export_comparison_html(differences, path)
            with open(path) as f:
                content = f.read()
            assert "MacBook Fingerprint Comparison" in content
            assert "SecuritySettingsCollector" in content
        finally:
            os.unlink(path)
