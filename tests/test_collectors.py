"""
Tests for collector modules.
"""

from unittest.mock import patch
from macos_fingerprint.collectors.base import (
    CollectorResult,
    CollectorRegistry
)
from macos_fingerprint.collectors.apps import InstalledAppsCollector
from macos_fingerprint.collectors.system import SystemInfoCollector


class TestBaseCollector:
    """Test base collector functionality."""

    def test_collector_result_success(self):
        """Test successful collector result."""
        result = CollectorResult(
            success=True,
            data={"test": "data"},
            collector_name="TestCollector"
        )
        assert result.success
        assert result.data == {"test": "data"}
        assert result.error is None

    def test_collector_result_error(self):
        """Test error collector result."""
        result = CollectorResult(
            success=False,
            data=None,
            error="Test error",
            collector_name="TestCollector"
        )
        assert not result.success
        assert result.data is None
        assert result.error == "Test error"


class TestCollectorRegistry:
    """Test collector registry."""

    def setup_method(self):
        """Clear registry before each test."""
        CollectorRegistry.clear()

    def test_register_collector(self):
        """Test registering a collector."""
        collector = InstalledAppsCollector()
        CollectorRegistry.register(collector)

        registered = CollectorRegistry.get_collector("InstalledAppsCollector")
        assert registered is not None
        assert registered.name == "InstalledAppsCollector"

    def test_get_all_collectors(self):
        """Test getting all collectors."""
        collector1 = InstalledAppsCollector()
        collector2 = SystemInfoCollector()

        CollectorRegistry.register(collector1)
        CollectorRegistry.register(collector2)

        all_collectors = CollectorRegistry.get_all_collectors()
        assert len(all_collectors) == 2

    def test_unregister_collector(self):
        """Test unregistering a collector."""
        collector = InstalledAppsCollector()
        CollectorRegistry.register(collector)

        CollectorRegistry.unregister("InstalledAppsCollector")
        assert CollectorRegistry.get_collector("InstalledAppsCollector") is None


@patch('macos_fingerprint.collectors.apps.run_command')
class TestInstalledAppsCollector:
    """Test installed apps collector."""

    def test_collect_success(self, mock_run_command):
        """Test successful collection."""
        mock_run_command.side_effect = [
            "App1.app\nApp2.app",  # System apps
            "UserApp.app"          # User apps
        ]

        collector = InstalledAppsCollector()
        result = collector.collect()

        assert result.success
        assert "system" in result.data
        assert "user" in result.data
        assert len(result.data["system"]) == 2
        assert len(result.data["user"]) == 1

    def test_collect_empty(self, mock_run_command):
        """Test collection with no apps."""
        mock_run_command.return_value = None

        collector = InstalledAppsCollector()
        result = collector.collect()

        assert result.success
        assert result.data["system"] == []
        assert result.data["user"] == []


@patch('macos_fingerprint.collectors.system.run_command')
class TestSystemInfoCollector:
    """Test system info collector."""

    def test_collect_success(self, mock_run_command):
        """Test successful collection."""
        mock_run_command.side_effect = [
            "ProductName: macOS\nProductVersion: 14.0",  # sw_vers
            "MacBook-Pro.local",                           # hostname
            "up 5 days",                                   # uptime
            "MacBookPro18,3",                              # hardware_model
            "Apple M1 Pro",                                # cpu_brand
            "17179869184"                                  # memory_size
        ]

        collector = SystemInfoCollector()
        result = collector.collect()

        assert result.success
        assert "sw_vers" in result.data
        assert "hostname" in result.data
        assert result.data["hostname"] == "MacBook-Pro.local"
