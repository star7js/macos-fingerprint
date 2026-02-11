"""
Base collector class and registry for system fingerprinting.
"""

import logging
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)


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

    def collect_all(
        self,
        parallel: bool = False,
        max_workers: int = 4,
        progress_callback: Optional[Callable] = None,
    ) -> Dict[str, CollectorResult]:
        """
        Execute all registered collectors.

        Args:
            parallel: Run collectors concurrently using threads.
            max_workers: Maximum thread-pool size when *parallel* is True.
            progress_callback: Optional callable(name, index, total) invoked
                               before/after each collector runs.

        Returns:
            Dictionary mapping collector names to results
        """
        items = list(self._collectors.items())
        total = len(items)

        if not parallel:
            results: Dict[str, CollectorResult] = {}
            for idx, (name, collector) in enumerate(items):
                if progress_callback is not None:
                    try:
                        progress_callback(name, idx, total)
                    except Exception:
                        pass
                results[name] = collector.safe_collect()
            return results

        # Parallel execution
        results = {}

        def _run(name: str, collector: BaseCollector, idx: int) -> tuple:
            if progress_callback is not None:
                try:
                    progress_callback(name, idx, total)
                except Exception:
                    pass
            return name, collector.safe_collect()

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_run, name, collector, idx): name
                for idx, (name, collector) in enumerate(items)
            }
            for future in as_completed(futures):
                try:
                    name, result = future.result()
                    results[name] = result
                except Exception as exc:
                    cname = futures[future]
                    logger.error("Collector %s raised: %s", cname, exc)
                    results[cname] = CollectorResult(
                        success=False, data=None, error=str(exc), collector_name=cname
                    )

        return results

    def clear(self) -> None:
        """Clear all registered collectors."""
        self._collectors.clear()


# Module-level default registry for convenience.
default_registry = CollectorRegistry()
