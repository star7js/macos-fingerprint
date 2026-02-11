"""
Tests for collector modules.
"""

from unittest.mock import patch
from macos_fingerprint.collectors.base import (
    CollectorResult,
    CollectorRegistry,
    CollectorCategory,
)
from macos_fingerprint.collectors.apps import InstalledAppsCollector
from macos_fingerprint.collectors.system import SystemInfoCollector


class TestBaseCollector:
    """Test base collector functionality."""

    def test_collector_result_success(self):
        """Test successful collector result."""
        result = CollectorResult(
            success=True, data={"test": "data"}, collector_name="TestCollector"
        )
        assert result.success
        assert result.data == {"test": "data"}
        assert result.error is None

    def test_collector_result_error(self):
        """Test error collector result."""
        result = CollectorResult(
            success=False, data=None, error="Test error", collector_name="TestCollector"
        )
        assert not result.success
        assert result.data is None
        assert result.error == "Test error"


class TestCollectorRegistry:
    """Test collector registry."""

    def test_register_collector(self):
        """Test registering a collector."""
        registry = CollectorRegistry()
        collector = InstalledAppsCollector()
        registry.register(collector)

        registered = registry.get_collector("InstalledAppsCollector")
        assert registered is not None
        assert registered.name == "InstalledAppsCollector"

    def test_get_all_collectors(self):
        """Test getting all collectors."""
        registry = CollectorRegistry()
        collector1 = InstalledAppsCollector()
        collector2 = SystemInfoCollector()

        registry.register(collector1)
        registry.register(collector2)

        all_collectors = registry.get_all_collectors()
        assert len(all_collectors) == 2

    def test_unregister_collector(self):
        """Test unregistering a collector."""
        registry = CollectorRegistry()
        collector = InstalledAppsCollector()
        registry.register(collector)

        registry.unregister("InstalledAppsCollector")
        assert registry.get_collector("InstalledAppsCollector") is None

    def test_clear_registry(self):
        """Test clearing the registry."""
        registry = CollectorRegistry()
        registry.register(InstalledAppsCollector())
        registry.register(SystemInfoCollector())
        assert len(registry.get_all_collectors()) == 2

        registry.clear()
        assert len(registry.get_all_collectors()) == 0

    def test_separate_instances_are_independent(self):
        """Test that two registry instances do not share state."""
        reg_a = CollectorRegistry()
        reg_b = CollectorRegistry()

        reg_a.register(InstalledAppsCollector())
        assert len(reg_a.get_all_collectors()) == 1
        assert len(reg_b.get_all_collectors()) == 0

    def test_get_collectors_by_category(self):
        """Test filtering collectors by category."""
        registry = CollectorRegistry()
        registry.register(InstalledAppsCollector())
        registry.register(SystemInfoCollector())

        apps = registry.get_collectors_by_category(CollectorCategory.APPS)
        assert len(apps) == 1
        assert apps[0].name == "InstalledAppsCollector"

    @patch("macos_fingerprint.collectors.apps.run_command")
    def test_collect_all(self, mock_run_command):
        """Test collecting from all registered collectors."""
        mock_run_command.return_value = None  # All commands return None
        registry = CollectorRegistry()
        registry.register(InstalledAppsCollector())

        results = registry.collect_all()
        assert "InstalledAppsCollector" in results
        assert results["InstalledAppsCollector"].success

    @patch("macos_fingerprint.collectors.apps.run_command")
    def test_collect_all_parallel(self, mock_run_command):
        """Test parallel collection."""
        mock_run_command.return_value = None
        registry = CollectorRegistry()
        registry.register(InstalledAppsCollector())
        registry.register(SystemInfoCollector())

        results = registry.collect_all(parallel=True, max_workers=2)
        assert "InstalledAppsCollector" in results
        assert "SystemInfoCollector" in results

    @patch("macos_fingerprint.collectors.apps.run_command")
    def test_collect_all_with_progress_callback(self, mock_run_command):
        """Test that progress callback is invoked."""
        mock_run_command.return_value = None
        registry = CollectorRegistry()
        registry.register(InstalledAppsCollector())

        calls = []
        def cb(name, idx, total):
            calls.append((name, idx, total))

        registry.collect_all(progress_callback=cb)
        assert len(calls) == 1
        assert calls[0] == ("InstalledAppsCollector", 0, 1)

    @patch("macos_fingerprint.collectors.apps.run_command")
    def test_collect_all_parallel_with_callback(self, mock_run_command):
        """Test progress callback in parallel mode."""
        mock_run_command.return_value = None
        registry = CollectorRegistry()
        registry.register(InstalledAppsCollector())

        calls = []
        def cb(name, idx, total):
            calls.append(name)

        registry.collect_all(parallel=True, max_workers=1, progress_callback=cb)
        assert "InstalledAppsCollector" in calls


@patch("macos_fingerprint.collectors.apps.run_command")
class TestInstalledAppsCollector:
    """Test installed apps collector."""

    def test_collect_success(self, mock_run_command):
        """Test successful collection."""
        mock_run_command.side_effect = [
            "App1.app\nApp2.app",  # System apps
            "UserApp.app",  # User apps
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


@patch("macos_fingerprint.collectors.system.run_command")
class TestSystemInfoCollector:
    """Test system info collector."""

    def test_collect_success(self, mock_run_command):
        """Test successful collection."""
        mock_run_command.side_effect = [
            "ProductName: macOS\nProductVersion: 14.0",  # sw_vers
            "MacBook-Pro.local",  # hostname
            "up 5 days",  # uptime
            "MacBookPro18,3",  # hardware_model
            "Apple M1 Pro",  # cpu_brand
            "17179869184",  # memory_size
        ]

        collector = SystemInfoCollector()
        result = collector.collect()

        assert result.success
        assert "sw_vers" in result.data
        assert "hostname" in result.data
        assert result.data["hostname"] == "MacBook-Pro.local"
