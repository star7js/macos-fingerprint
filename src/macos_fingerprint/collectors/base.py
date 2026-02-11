"""
Base collector class and registry for system fingerprinting.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from enum import Enum


class CollectorCategory(Enum):
    """Categories for organizing collectors."""

    APPS = "applications"
    SYSTEM = "system"
    NETWORK = "network"
    SECURITY = "security"
    HARDWARE = "hardware"
    USER = "user"
    DEVELOPER = "developer"


@dataclass
class CollectorResult:
    """Result from a collector execution."""

    success: bool
    data: Any
    error: Optional[str] = None
    collector_name: Optional[str] = None


class BaseCollector(ABC):
    """
    Abstract base class for all fingerprint collectors.

    Each collector gathers specific system information and returns
    it in a structured format.
    """

    def __init__(self):
        self.name = self.__class__.__name__
        self.category = CollectorCategory.SYSTEM  # Override in subclasses

    @abstractmethod
    def collect(self) -> CollectorResult:
        """
        Collect fingerprint data.

        Returns:
            CollectorResult with success status and collected data
        """
        pass

    def safe_collect(self) -> CollectorResult:
        """
        Safely execute collection with error handling.

        Returns:
            CollectorResult, even if collection fails
        """
        try:
            return self.collect()
        except Exception as e:
            return CollectorResult(
                success=False, data=None, error=str(e), collector_name=self.name
            )


class CollectorRegistry:
    """
    Registry for collector discovery and management.

    Each instance maintains its own independent set of collectors,
    avoiding shared mutable class-level state.
    """

    def __init__(self) -> None:
        self._collectors: Dict[str, BaseCollector] = {}

    def register(self, collector: BaseCollector) -> None:
        """
        Register a collector.

        Args:
            collector: Collector instance to register
        """
        self._collectors[collector.name] = collector

    def unregister(self, name: str) -> None:
        """
        Unregister a collector by name.

        Args:
            name: Name of collector to unregister
        """
        if name in self._collectors:
            del self._collectors[name]

    def get_collector(self, name: str) -> Optional[BaseCollector]:
        """
        Get a collector by name.

        Args:
            name: Collector name

        Returns:
            Collector instance or None
        """
        return self._collectors.get(name)

    def get_all_collectors(self) -> List[BaseCollector]:
        """
        Get all registered collectors.

        Returns:
            List of all collector instances
        """
        return list(self._collectors.values())

    def get_collectors_by_category(
        self, category: CollectorCategory
    ) -> List[BaseCollector]:
        """
        Get collectors by category.

        Args:
            category: Category to filter by

        Returns:
            List of collectors in the category
        """
        return [
            collector
            for collector in self._collectors.values()
            if collector.category == category
        ]

    def collect_all(self) -> Dict[str, CollectorResult]:
        """
        Execute all registered collectors.

        Returns:
            Dictionary mapping collector names to results
        """
        results = {}
        for name, collector in self._collectors.items():
            results[name] = collector.safe_collect()
        return results

    def clear(self) -> None:
        """Clear all registered collectors."""
        self._collectors.clear()


# Module-level default registry for convenience.
default_registry = CollectorRegistry()
