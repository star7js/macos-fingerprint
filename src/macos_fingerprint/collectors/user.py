"""
User-related collectors for accounts and user-specific information.
"""

from .base import BaseCollector, CollectorResult, CollectorCategory
from ..utils.commands import run_command


class UserAccountsCollector(BaseCollector):
    """Collect user accounts on the system."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.USER

    def collect(self) -> CollectorResult:
        result = run_command(["dscl", ".", "-list", "/Users"])
        data = result.split('\n') if result else []

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )
