"""
Security-related collectors for system security status.
"""

from .base import BaseCollector, CollectorResult, CollectorCategory
from ..utils.commands import run_command


class SecuritySettingsCollector(BaseCollector):
    """Collect FileVault, firewall, and SIP status."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SECURITY

    def collect(self) -> CollectorResult:
        filevault = run_command(["fdesetup", "status"])
        firewall = run_command([
            "defaults", "read",
            "/Library/Preferences/com.apple.alf", "globalstate"
        ])
        sip = run_command(["csrutil", "status"])

        data = {
            "filevault": filevault if filevault else "",
            "firewall": firewall if firewall else "",
            "sip": sip if sip else ""
        }

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class GatekeeperCollector(BaseCollector):
    """Collect Gatekeeper status."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SECURITY

    def collect(self) -> CollectorResult:
        status = run_command(["spctl", "--status"])

        data = {
            "status": status if status else ""
        }

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class XProtectCollector(BaseCollector):
    """Collect XProtect version information."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SECURITY

    def collect(self) -> CollectorResult:
        # XProtect version can be found in the plist
        xprotect_version = run_command([
            "defaults", "read",
            "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
            "CFBundleShortVersionString"
        ])

        data = {
            "version": xprotect_version if xprotect_version else ""
        }

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class MRTCollector(BaseCollector):
    """Collect Malware Removal Tool (MRT) version."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SECURITY

    def collect(self) -> CollectorResult:
        # MRT version from plist
        mrt_version = run_command([
            "defaults", "read",
            "/System/Library/CoreServices/MRT.app/Contents/Info.plist",
            "CFBundleShortVersionString"
        ])

        data = {
            "version": mrt_version if mrt_version else ""
        }

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )
