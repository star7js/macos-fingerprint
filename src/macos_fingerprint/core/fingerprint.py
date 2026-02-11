"""
Core fingerprinting functionality.
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Optional

from ..collectors.base import CollectorRegistry, default_registry
from ..collectors import apps, system, network, security, user, developer
from ..utils.crypto import hash_fingerprint_data


def register_all_collectors(registry: Optional[CollectorRegistry] = None):
    """Register all available collectors.

    Args:
        registry: Registry instance to populate. Uses the default
                  module-level registry when *None*.
    """
    if registry is None:
        registry = default_registry

    # Apps
    registry.register(apps.InstalledAppsCollector())
    registry.register(apps.BrowserExtensionsCollector())
    registry.register(apps.LaunchAgentsCollector())
    registry.register(apps.StartupItemsCollector())

    # System
    registry.register(system.SystemInfoCollector())
    registry.register(system.KernelExtensionsCollector())
    registry.register(system.PrintersCollector())
    registry.register(system.BluetoothDevicesCollector())
    registry.register(system.TimeMachineCollector())

    # Network
    registry.register(network.NetworkConfigCollector())
    registry.register(network.OpenPortsCollector())
    registry.register(network.NetworkConnectionsCollector())
    registry.register(network.SSHConfigCollector())
    registry.register(network.HostsFileCollector())
    registry.register(network.NetworkSharesCollector())

    # Security
    registry.register(security.SecuritySettingsCollector())
    registry.register(security.GatekeeperCollector())
    registry.register(security.XProtectCollector())
    registry.register(security.MRTCollector())

    # User
    registry.register(user.UserAccountsCollector())

    # Developer
    registry.register(developer.HomebrewCollector())
    registry.register(developer.PipPackagesCollector())
    registry.register(developer.NpmPackagesCollector())
    registry.register(developer.XcodeCollector())


def create_fingerprint(
    hash_sensitive: bool = True,
    registry: Optional[CollectorRegistry] = None,
) -> Dict[str, Any]:
    """
    Create a system fingerprint by running all collectors.

    Args:
        hash_sensitive: Whether to hash sensitive fields (default: True)
        registry: Optional registry instance. A fresh default registry
                  is used when *None*.

    Returns:
        Dictionary containing fingerprint data
    """
    if registry is None:
        # Build a fresh registry every time so callers get a clean,
        # self-contained set of collectors.
        registry = CollectorRegistry()
        register_all_collectors(registry)

    # Collect all data
    results = registry.collect_all()

    # Build fingerprint structure
    fingerprint: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "collectors": {},
    }

    # Add successful collector results
    for name, result in results.items():
        if result.success:
            fingerprint["collectors"][name] = result.data
        else:
            fingerprint["collectors"][name] = {"error": result.error}

    # Hash sensitive fields if requested
    if hash_sensitive:
        fingerprint = hash_fingerprint_data(fingerprint)

    return fingerprint


def hash_fingerprint(fingerprint: Dict[str, Any]) -> str:
    """
    Generate a SHA-256 hash of the entire fingerprint.

    Args:
        fingerprint: Fingerprint dictionary

    Returns:
        Hex-encoded hash string
    """
    serialized = json.dumps(fingerprint, sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()
