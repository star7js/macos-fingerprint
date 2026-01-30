"""
Developer environment collectors for Homebrew, pip, npm, and Xcode.
"""

from .base import BaseCollector, CollectorResult, CollectorCategory
from ..utils.commands import run_command


class HomebrewCollector(BaseCollector):
    """Collect Homebrew packages (formulas and casks)."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.DEVELOPER

    def collect(self) -> CollectorResult:
        # Get installed formulas
        formulas = run_command(["brew", "list", "--formula"])
        # Get installed casks
        casks = run_command(["brew", "list", "--cask"])

        data = {
            "formulas": formulas.split('\n') if formulas else [],
            "casks": casks.split('\n') if casks else []
        }

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class PipPackagesCollector(BaseCollector):
    """Collect globally installed pip packages."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.DEVELOPER

    def collect(self) -> CollectorResult:
        # Get pip packages (prefer pip3)
        result = run_command(["pip3", "list"])
        if not result:
            result = run_command(["pip", "list"])

        data = result.split('\n') if result else []

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class NpmPackagesCollector(BaseCollector):
    """Collect globally installed npm packages."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.DEVELOPER

    def collect(self) -> CollectorResult:
        result = run_command(["npm", "list", "-g", "--depth=0"])
        data = result.split('\n') if result else []

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )


class XcodeCollector(BaseCollector):
    """Collect Xcode version information."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.DEVELOPER

    def collect(self) -> CollectorResult:
        version = run_command(["xcodebuild", "-version"])
        selected_path = run_command(["xcode-select", "-p"])

        data = {
            "version": version.split('\n') if version else [],
            "selected_path": selected_path if selected_path else ""
        }

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )
