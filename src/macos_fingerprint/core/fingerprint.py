"""
Core fingerprinting functionality.
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Callable, Dict, Any, List, Optional, Set

from ..collectors.base import CollectorRegistry
from ..collectors import apps, system, network, security, user, developer
from ..utils.crypto import hash_fingerprint_data

logger = logging.getLogger(__name__)

# Canonical list of all collector names for validation / listing.
ALL_COLLECTOR_NAMES: List[str] = [
    "InstalledAppsCollector",
    "BrowserExtensionsCollector",
    "LaunchAgentsCollector",
    "StartupItemsCollector",
    "SystemInfoCollector",
    "KernelExtensionsCollector",
    "PrintersCollector",
    "BluetoothDevicesCollector",
    "TimeMachineCollector",
    "NetworkConfigCollector",
    "OpenPortsCollector",
    "NetworkConnectionsCollector",
    "SSHConfigCollector",
    "HostsFileCollector",
    "NetworkSharesCollector",
    "SecuritySettingsCollector",
    "GatekeeperCollector",
    "XProtectCollector",
    "MRTCollector",
    "UserAccountsCollector",
    "HomebrewCollector",
    "PipPackagesCollector",
    "NpmPackagesCollector",
    "XcodeCollector",
]


def register_all_collectors(registry: CollectorRegistry):
    """Register all available collectors.

    Args:
        registry: Registry instance to populate.
    """
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
    collectors: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    progress_callback: Optional[Callable] = None,
    parallel: bool = False,
    max_workers: int = 4,
) -> Dict[str, Any]:
    """
    Create a system fingerprint by running all collectors.

    Args:
        hash_sensitive: Whether to hash sensitive fields (default: True)
        registry: Optional registry instance. A fresh default registry
                  is used when *None*.
        collectors: Optional list of collector names to include (whitelist).
                    When set, only these collectors will run.
        exclude: Optional list of collector names to exclude (blacklist).
                 Applied after the *collectors* whitelist.
        progress_callback: Optional callable(collector_name, index, total)
                           invoked before each collector runs.
        parallel: Run collectors concurrently with ThreadPoolExecutor.
        max_workers: Max threads when *parallel* is True (default 4).

    Returns:
        Dictionary containing fingerprint data
    """
    if registry is None:
        # Build a fresh registry every time so callers get a clean,
        # self-contained set of collectors.
        registry = CollectorRegistry()
        register_all_collectors(registry)

    # Apply --collectors whitelist: remove anything not requested.
    if collectors:
        include_set: Set[str] = set(collectors)
        all_names = [c.name for c in registry.get_all_collectors()]
        for name in all_names:
            if name not in include_set:
                registry.unregister(name)

    # Apply --exclude blacklist: remove excluded collectors.
    if exclude:
        for name in exclude:
            registry.unregister(name)

    # Collect all data
    results = registry.collect_all(
        parallel=parallel,
        max_workers=max_workers,
        progress_callback=progress_callback,
    )

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
    Generate a SHA3-256 hash of the entire fingerprint.

    Args:
        fingerprint: Fingerprint dictionary

    Returns:
        Hex-encoded hash string
    """
    serialized = json.dumps(fingerprint, sort_keys=True).encode("utf-8")
    return hashlib.sha3_256(serialized).hexdigest()
