"""
Application collectors for installed apps, extensions, and launch agents.
"""

import os
from .base import BaseCollector, CollectorResult, CollectorCategory
from ..utils.commands import run_command, split_lines


class InstalledAppsCollector(BaseCollector):
    """Collect installed applications from system and user directories."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.APPS

    def collect(self) -> CollectorResult:
        system_apps = run_command(["ls", "-1", "/Applications"])
        user_apps = run_command(["ls", "-1", os.path.expanduser("~/Applications")])

        data = {
            "system": split_lines(system_apps),
            "user": split_lines(user_apps),
        }

        return CollectorResult(success=True, data=data, collector_name=self.name)


class BrowserExtensionsCollector(BaseCollector):
    """Collect browser extensions for Safari, Chrome, and Firefox."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.APPS

    def collect(self) -> CollectorResult:
        safari_extensions = run_command(
            ["ls", "-1", os.path.expanduser("~/Library/Safari/Extensions")]
        )
        chrome_extensions = run_command(
            [
                "ls",
                "-1",
                os.path.expanduser(
                    "~/Library/Application Support/Google/Chrome/Default/Extensions"
                ),
            ]
        )
        firefox_extensions = run_command(
            [
                "ls",
                "-1",
                os.path.expanduser("~/Library/Application Support/Firefox/Profiles"),
            ]
        )

        data = {
            "safari": split_lines(safari_extensions),
            "chrome": split_lines(chrome_extensions),
            "firefox": split_lines(firefox_extensions),
        }

        return CollectorResult(success=True, data=data, collector_name=self.name)


class LaunchAgentsCollector(BaseCollector):
    """Collect launch agents and daemons."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.APPS

    def collect(self) -> CollectorResult:
        system_agents = run_command(
            ["ls", "-1", "/Library/LaunchAgents", "/Library/LaunchDaemons"]
        )
        user_agents = run_command(
            ["ls", "-1", os.path.expanduser("~/Library/LaunchAgents")]
        )

        data = {
            "system": split_lines(system_agents),
            "user": split_lines(user_agents),
        }

        return CollectorResult(success=True, data=data, collector_name=self.name)


class StartupItemsCollector(BaseCollector):
    """Collect startup/login items."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.APPS

    def collect(self) -> CollectorResult:
        result = run_command(
            [
                "osascript",
                "-e",
                'tell application "System Events" to get the name of every login item',
            ]
        )

        data = result.split(", ") if result else []

        return CollectorResult(success=True, data=data, collector_name=self.name)
