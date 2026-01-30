"""
Pytest configuration and fixtures.
"""

import pytest


@pytest.fixture
def sample_fingerprint():
    """Sample fingerprint for testing."""
    return {
        "timestamp": "2026-01-01T00:00:00",
        "collectors": {
            "InstalledAppsCollector": {
                "system": ["App1.app", "App2.app"],
                "user": ["UserApp.app"]
            },
            "SystemInfoCollector": {
                "hostname": "test-mac.local",
                "sw_vers": ["ProductName: macOS", "ProductVersion: 14.0"]
            },
            "NetworkConfigCollector": {
                "ip_addresses": {"en0": "192.168.1.100"},
                "interfaces": ["en0", "en1"]
            }
        }
    }


@pytest.fixture
def sample_baseline():
    """Sample baseline fingerprint."""
    return {
        "timestamp": "2026-01-01T00:00:00",
        "collectors": {
            "InstalledAppsCollector": {
                "system": ["App1.app"],
                "user": []
            }
        }
    }


@pytest.fixture
def sample_current():
    """Sample current fingerprint with changes."""
    return {
        "timestamp": "2026-01-02T00:00:00",
        "collectors": {
            "InstalledAppsCollector": {
                "system": ["App1.app", "App2.app", "App3.app"],
                "user": ["UserApp.app"]
            }
        }
    }
