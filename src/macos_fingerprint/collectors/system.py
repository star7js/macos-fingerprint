"""
System information collectors for hardware, OS, and kernel extensions.
"""

import os
from .base import BaseCollector, CollectorResult, CollectorCategory
from ..utils.commands import run_command


class SystemInfoCollector(BaseCollector):
    """Collect macOS version and system information."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SYSTEM

    def collect(self) -> CollectorResult:
        sw_vers = run_command(["sw_vers"])
        hostname = run_command(["hostname"])
        uptime = run_command(["uptime"])

        # Get hardware info
        hardware_model = run_command(["sysctl", "-n", "hw.model"])
        cpu_brand = run_command(["sysctl", "-n", "machdep.cpu.brand_string"])
        memory_size = run_command(["sysctl", "-n", "hw.memsize"])

        data = {
            "sw_vers": sw_vers.split('\n') if sw_vers else [],
            "hostname": hostname if hostname else "",
            "uptime": uptime if uptime else "",
            "hardware_model": hardware_model if hardware_model else "",
            "cpu_brand": cpu_brand if cpu_brand else "",
            "memory_size": memory_size if memory_size else ""
        }

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class KernelExtensionsCollector(BaseCollector):
    """Collect loaded kernel extensions."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SYSTEM

    def collect(self) -> CollectorResult:
        result = run_command(["kextstat", "-l"])
        data = result.split('\n') if result else []

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class PrintersCollector(BaseCollector):
    """Collect installed printers."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SYSTEM

    def collect(self) -> CollectorResult:
        result = run_command(["lpstat", "-p"])
        data = result.split('\n') if result else []

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class BluetoothDevicesCollector(BaseCollector):
    """Collect Bluetooth devices."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.HARDWARE

    def collect(self) -> CollectorResult:
        result = run_command(["system_profiler", "SPBluetoothDataType"])
        data = result.split('\n') if result else []

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class TimeMachineCollector(BaseCollector):
    """Collect Time Machine backup information."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SYSTEM

    def collect(self) -> CollectorResult:
        result = run_command(["tmutil", "destinationinfo"])
        data = result.split('\n') if result else []

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )
