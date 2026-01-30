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
                success=False,
                data=None,
                error=str(e),
                collector_name=self.name
            )


class CollectorRegistry:
    """
    Registry for automatic collector discovery and management.
    """

    _collectors: Dict[str, BaseCollector] = {}

    @classmethod
    def register(cls, collector: BaseCollector) -> None:
        """
        Register a collector.

        Args:
            collector: Collector instance to register
        """
        cls._collectors[collector.name] = collector

    @classmethod
    def unregister(cls, name: str) -> None:
        """
        Unregister a collector by name.

        Args:
            name: Name of collector to unregister
        """
        if name in cls._collectors:
            del cls._collectors[name]

    @classmethod
    def get_collector(cls, name: str) -> Optional[BaseCollector]:
        """
        Get a collector by name.

        Args:
            name: Collector name

        Returns:
            Collector instance or None
        """
        return cls._collectors.get(name)

    @classmethod
    def get_all_collectors(cls) -> List[BaseCollector]:
        """
        Get all registered collectors.

        Returns:
            List of all collector instances
        """
        return list(cls._collectors.values())

    @classmethod
    def get_collectors_by_category(cls, category: CollectorCategory) -> List[BaseCollector]:
        """
        Get collectors by category.

        Args:
            category: Category to filter by

        Returns:
            List of collectors in the category
        """
        return [
            collector for collector in cls._collectors.values()
            if collector.category == category
        ]

    @classmethod
    def collect_all(cls) -> Dict[str, CollectorResult]:
        """
        Execute all registered collectors.

        Returns:
            Dictionary mapping collector names to results
        """
        results = {}
        for name, collector in cls._collectors.items():
            results[name] = collector.safe_collect()
        return results

    @classmethod
    def clear(cls) -> None:
        """Clear all registered collectors."""
        cls._collectors.clear()
