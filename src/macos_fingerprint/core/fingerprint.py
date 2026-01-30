"""
Core fingerprinting functionality.
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, Any

from ..collectors.base import CollectorRegistry
from ..collectors import apps, system, network, security, user, developer
from ..utils.crypto import hash_fingerprint_data


def register_all_collectors():
    """Register all available collectors."""
    # Apps
    CollectorRegistry.register(apps.InstalledAppsCollector())
    CollectorRegistry.register(apps.BrowserExtensionsCollector())
    CollectorRegistry.register(apps.LaunchAgentsCollector())
    CollectorRegistry.register(apps.StartupItemsCollector())

    # System
    CollectorRegistry.register(system.SystemInfoCollector())
    CollectorRegistry.register(system.KernelExtensionsCollector())
    CollectorRegistry.register(system.PrintersCollector())
    CollectorRegistry.register(system.BluetoothDevicesCollector())
    CollectorRegistry.register(system.TimeMachineCollector())

    # Network
    CollectorRegistry.register(network.NetworkConfigCollector())
    CollectorRegistry.register(network.OpenPortsCollector())
    CollectorRegistry.register(network.NetworkConnectionsCollector())
    CollectorRegistry.register(network.SSHConfigCollector())
    CollectorRegistry.register(network.HostsFileCollector())
    CollectorRegistry.register(network.NetworkSharesCollector())
    CollectorRegistry.register(network.BonjourServicesCollector())

    # Security
    CollectorRegistry.register(security.SecuritySettingsCollector())
    CollectorRegistry.register(security.GatekeeperCollector())
    CollectorRegistry.register(security.XProtectCollector())
    CollectorRegistry.register(security.MRTCollector())

    # User
    CollectorRegistry.register(user.UserAccountsCollector())

    # Developer
    CollectorRegistry.register(developer.HomebrewCollector())
    CollectorRegistry.register(developer.PipPackagesCollector())
    CollectorRegistry.register(developer.NpmPackagesCollector())
    CollectorRegistry.register(developer.XcodeCollector())


def create_fingerprint(hash_sensitive: bool = True) -> Dict[str, Any]:
    """
    Create a system fingerprint by running all collectors.

    Args:
        hash_sensitive: Whether to hash sensitive fields (default: True)

    Returns:
        Dictionary containing fingerprint data
    """
    # Register collectors if not already registered
    if not CollectorRegistry.get_all_collectors():
        register_all_collectors()

    # Collect all data
    results = CollectorRegistry.collect_all()

    # Build fingerprint structure
    fingerprint = {"timestamp": datetime.now().isoformat(), "collectors": {}}

    # Add successful collector results
    for name, result in results.items():
        if result.success:
            fingerprint["collectors"][name] = result.data  # type: ignore[index]
        else:
            fingerprint["collectors"][name] = {"error": result.error}  # type: ignore[index]

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
