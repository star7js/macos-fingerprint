"""
Tests for fingerprint comparison.
"""

import pytest
from macos_fingerprint.core.comparison import (
    compare_lists,
    compare_dicts,
    compare_fingerprints,
    ChangeSeverity,
    classify_severity,
    ChangeType
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


class TestCompareFingerprints:
    """Test full fingerprint comparison."""

    def test_compare_identical_fingerprints(self):
        """Test comparing identical fingerprints."""
        fingerprint = {
            "timestamp": "2026-01-01T00:00:00",
            "collectors": {
                "InstalledAppsCollector": {"system": ["App1", "App2"]}
            }
        }

        result = compare_fingerprints(fingerprint, fingerprint)

        assert result["summary"]["total_changes"] == 0

    def test_compare_with_changes(self):
        """Test comparing fingerprints with changes."""
        baseline = {
            "timestamp": "2026-01-01T00:00:00",
            "collectors": {
                "InstalledAppsCollector": {"system": ["App1", "App2"]}
            }
        }

        current = {
            "timestamp": "2026-01-02T00:00:00",
            "collectors": {
                "InstalledAppsCollector": {"system": ["App1", "App2", "App3"]}
            }
        }

        result = compare_fingerprints(baseline, current)

        assert result["summary"]["total_changes"] > 0
        assert "InstalledAppsCollector" in result["changes"]
