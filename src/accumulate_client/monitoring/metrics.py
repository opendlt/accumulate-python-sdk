"""
Metrics collection and registry for telemetry.

Provides thread-safe metrics collection with counters, gauges,
histograms, and timers for comprehensive observability.
"""

import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Callable
import statistics


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class MetricValue:
    """Value of a metric at a point in time."""
    value: Union[int, float]
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)


class Metric(ABC):
    """
    Abstract base class for metrics.

    Defines the interface for all metric types with thread-safe
    operations and label support.
    """

    def __init__(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None):
        """
        Initialize metric.

        Args:
            name: Metric name
            description: Metric description
            labels: Default labels
        """
        self.name = name
        self.description = description
        self.default_labels = labels or {}
        self._lock = threading.RLock()
        self._created_at = time.time()

    @property
    @abstractmethod
    def metric_type(self) -> MetricType:
        """Get metric type."""
        pass

    @abstractmethod
    def get_value(self, labels: Optional[Dict[str, str]] = None) -> Union[int, float, Dict[str, Any]]:
        """Get current metric value."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset metric to initial state."""
        pass

    def _merge_labels(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Merge provided labels with default labels."""
        merged = self.default_labels.copy()
        if labels:
            merged.update(labels)
        return merged

    def get_info(self) -> Dict[str, Any]:
        """Get metric information."""
        return {
            "name": self.name,
            "type": self.metric_type.value,
            "description": self.description,
            "created_at": self._created_at,
            "default_labels": self.default_labels
        }


class Counter(Metric):
    """
    Counter metric that only increases.

    Thread-safe counter with label support for tracking
    cumulative values like request counts or error rates.
    """

    def __init__(self, name: str, description: str = "", labels: Optional[Union[Dict[str, str], List[str]]] = None):
        """Initialize counter."""
        # Handle both dict (current) and list (legacy) label formats
        if isinstance(labels, list):
            # Legacy format: labels is a list of label names
            self._label_names = labels
            labels_dict = {}
        else:
            # Current format: labels is a dict of default values
            self._label_names = list(labels.keys()) if labels else []
            labels_dict = labels

        super().__init__(name, description, labels_dict)
        self._values: Dict[str, float] = defaultdict(float)

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.COUNTER

    def increment(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Increment counter.

        Args:
            amount: Amount to increment (must be >= 0)
            labels: Optional labels
        """
        if amount < 0:
            raise ValueError("Counter increment must be >= 0")

        with self._lock:
            label_key = self._labels_to_key(self._merge_labels(labels))
            self._values[label_key] += amount

    def get_value(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get counter value."""
        with self._lock:
            label_key = self._labels_to_key(self._merge_labels(labels))
            return self._values[label_key]

    def get_all_values(self) -> Dict[str, float]:
        """Get all counter values by label combination."""
        with self._lock:
            return dict(self._values)

    def reset(self) -> None:
        """Reset counter."""
        with self._lock:
            self._values.clear()

    def labels(self, **kwargs) -> 'Counter':
        """Create a labeled version of this counter for test compatibility."""
        # Create a new counter instance with the specific label values
        labeled_counter = Counter(f"{self.name}_labeled", self.description)
        labeled_counter._base_counter = self
        labeled_counter._label_values = kwargs
        return labeled_counter

    def _labels_to_key(self, labels: Dict[str, str]) -> str:
        """Convert labels dict to string key."""
        if not labels:
            return ""
        return "|".join(f"{k}={v}" for k, v in sorted(labels.items()))


class Gauge(Metric):
    """
    Gauge metric that can increase or decrease.

    Thread-safe gauge with label support for tracking
    current values like active connections or memory usage.
    """

    def __init__(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None):
        """Initialize gauge."""
        super().__init__(name, description, labels)
        self._values: Dict[str, float] = defaultdict(float)

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.GAUGE

    def set(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Set gauge value.

        Args:
            value: New value
            labels: Optional labels
        """
        with self._lock:
            label_key = self._labels_to_key(self._merge_labels(labels))
            self._values[label_key] = value

    def increment(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Increment gauge value.

        Args:
            amount: Amount to increment
            labels: Optional labels
        """
        with self._lock:
            label_key = self._labels_to_key(self._merge_labels(labels))
            self._values[label_key] += amount

    def decrement(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Decrement gauge value.

        Args:
            amount: Amount to decrement
            labels: Optional labels
        """
        self.increment(-amount, labels)

    def get_value(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get gauge value."""
        with self._lock:
            label_key = self._labels_to_key(self._merge_labels(labels))
            return self._values[label_key]

    def get_all_values(self) -> Dict[str, float]:
        """Get all gauge values by label combination."""
        with self._lock:
            return dict(self._values)

    def reset(self) -> None:
        """Reset gauge."""
        with self._lock:
            self._values.clear()

    def _labels_to_key(self, labels: Dict[str, str]) -> str:
        """Convert labels dict to string key."""
        if not labels:
            return ""
        return "|".join(f"{k}={v}" for k, v in sorted(labels.items()))


class Histogram(Metric):
    """
    Histogram metric for tracking distributions.

    Thread-safe histogram with configurable buckets for tracking
    distributions of values like request durations or response sizes.
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: Optional[List[float]] = None,
        labels: Optional[Dict[str, str]] = None
    ):
        """
        Initialize histogram.

        Args:
            name: Metric name
            description: Metric description
            buckets: Bucket boundaries (defaults to exponential buckets)
            labels: Default labels
        """
        super().__init__(name, description, labels)
        self.buckets = buckets or self._default_buckets()
        self._buckets_data: Dict[str, Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._sums: Dict[str, float] = defaultdict(float)
        self._counts: Dict[str, int] = defaultdict(int)

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.HISTOGRAM

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Observe a value.

        Args:
            value: Value to observe
            labels: Optional labels
        """
        with self._lock:
            label_key = self._labels_to_key(self._merge_labels(labels))

            # Update buckets
            for bucket in self.buckets:
                if value <= bucket:
                    self._buckets_data[label_key][bucket] += 1

            # Update sum and count
            self._sums[label_key] += value
            self._counts[label_key] += 1

    def get_value(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get histogram statistics."""
        with self._lock:
            label_key = self._labels_to_key(self._merge_labels(labels))

            bucket_counts = dict(self._buckets_data[label_key])
            total_sum = self._sums[label_key]
            total_count = self._counts[label_key]

            result = {
                "buckets": bucket_counts,
                "sum": total_sum,
                "count": total_count,
                "average": total_sum / max(total_count, 1)
            }

            return result

    def get_all_values(self) -> Dict[str, Dict[str, Any]]:
        """Get all histogram values by label combination."""
        with self._lock:
            result = {}
            for label_key in self._counts.keys():
                labels = self._key_to_labels(label_key)
                result[label_key] = self.get_value(labels)
            return result

    def reset(self) -> None:
        """Reset histogram."""
        with self._lock:
            self._buckets_data.clear()
            self._sums.clear()
            self._counts.clear()

    def _default_buckets(self) -> List[float]:
        """Generate default exponential buckets."""
        buckets = []
        for i in range(10):
            buckets.append(0.001 * (2 ** i))  # 1ms to ~1s
        buckets.extend([5.0, 10.0, 30.0, 60.0, float('inf')])
        return buckets

    def _labels_to_key(self, labels: Dict[str, str]) -> str:
        """Convert labels dict to string key."""
        if not labels:
            return ""
        return "|".join(f"{k}={v}" for k, v in sorted(labels.items()))

    def _key_to_labels(self, key: str) -> Dict[str, str]:
        """Convert string key back to labels dict."""
        if not key:
            return {}
        pairs = key.split("|")
        return dict(pair.split("=", 1) for pair in pairs if "=" in pair)


class Timer(Metric):
    """
    Timer metric for measuring durations.

    Combines histogram for duration distribution with
    counters for total time and operation counts.
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: Optional[List[float]] = None,
        labels: Optional[Dict[str, str]] = None
    ):
        """Initialize timer."""
        super().__init__(name, description, labels)
        self._histogram = Histogram(f"{name}_duration", f"{description} duration", buckets, labels)
        self._total_time = Counter(f"{name}_total", f"{description} total time", labels)
        self._count = Counter(f"{name}_count", f"{description} count", labels)

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.TIMER

    def time(self, labels: Optional[Dict[str, str]] = None):
        """
        Context manager for timing operations.

        Args:
            labels: Optional labels

        Returns:
            Context manager for timing
        """
        return TimerContext(self, labels)

    def observe(self, duration: float, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Observe a duration.

        Args:
            duration: Duration in seconds
            labels: Optional labels
        """
        with self._lock:
            self._histogram.observe(duration, labels)
            self._total_time.increment(duration, labels)
            self._count.increment(1, labels)

    def get_stats(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Get timer statistics.

        Args:
            labels: Optional labels

        Returns:
            Statistics dictionary with count, sum, mean, etc.
        """
        with self._lock:
            count = self._count.get_value(labels)
            total_time = self._total_time.get_value(labels)

            stats = {
                'count': int(count),
                'sum': total_time
            }

            if count > 0:
                stats['mean'] = total_time / count
            else:
                stats['mean'] = 0.0

            return stats

    def get_value(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get timer statistics."""
        histogram_stats = self._histogram.get_value(labels)
        total_time = self._total_time.get_value(labels)
        count = self._count.get_value(labels)

        return {
            "count": count,
            "total_time": total_time,
            "average_time": total_time / max(count, 1),
            "distribution": histogram_stats
        }

    def reset(self) -> None:
        """Reset timer."""
        with self._lock:
            self._histogram.reset()
            self._total_time.reset()
            self._count.reset()


class TimerContext:
    """Context manager for timing operations."""

    def __init__(self, timer: Timer, labels: Optional[Dict[str, str]] = None):
        """
        Initialize timer context.

        Args:
            timer: Timer metric
            labels: Optional labels
        """
        self.timer = timer
        self.labels = labels
        self.start_time = 0.0

    def __enter__(self):
        """Start timing."""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop timing and record duration."""
        duration = time.time() - self.start_time
        self.timer.observe(duration, self.labels)


class MetricsRegistry:
    """
    Registry for managing metrics.

    Thread-safe registry that maintains all metrics and provides
    utilities for creation, retrieval, and bulk operations.
    """

    def __init__(self):
        """Initialize metrics registry."""
        self._metrics: Dict[str, Metric] = {}
        self._lock = threading.RLock()

    def counter(
        self,
        name: str,
        description: str = "",
        labels: Optional[Dict[str, str]] = None
    ) -> Counter:
        """
        Get or create a counter metric.

        Args:
            name: Metric name
            description: Metric description
            labels: Default labels

        Returns:
            Counter metric
        """
        with self._lock:
            if name in self._metrics:
                metric = self._metrics[name]
                if not isinstance(metric, Counter):
                    raise ValueError(f"Metric {name} exists but is not a Counter")
                return metric

            counter = Counter(name, description, labels)
            self._metrics[name] = counter
            return counter

    def gauge(
        self,
        name: str,
        description: str = "",
        labels: Optional[Dict[str, str]] = None
    ) -> Gauge:
        """
        Get or create a gauge metric.

        Args:
            name: Metric name
            description: Metric description
            labels: Default labels

        Returns:
            Gauge metric
        """
        with self._lock:
            if name in self._metrics:
                metric = self._metrics[name]
                if not isinstance(metric, Gauge):
                    raise ValueError(f"Metric {name} exists but is not a Gauge")
                return metric

            gauge = Gauge(name, description, labels)
            self._metrics[name] = gauge
            return gauge

    def histogram(
        self,
        name: str,
        description: str = "",
        buckets: Optional[List[float]] = None,
        labels: Optional[Dict[str, str]] = None
    ) -> Histogram:
        """
        Get or create a histogram metric.

        Args:
            name: Metric name
            description: Metric description
            buckets: Histogram buckets
            labels: Default labels

        Returns:
            Histogram metric
        """
        with self._lock:
            if name in self._metrics:
                metric = self._metrics[name]
                if not isinstance(metric, Histogram):
                    raise ValueError(f"Metric {name} exists but is not a Histogram")
                return metric

            histogram = Histogram(name, description, buckets, labels)
            self._metrics[name] = histogram
            return histogram

    def timer(
        self,
        name: str,
        description: str = "",
        buckets: Optional[List[float]] = None,
        labels: Optional[Dict[str, str]] = None
    ) -> Timer:
        """
        Get or create a timer metric.

        Args:
            name: Metric name
            description: Metric description
            buckets: Duration buckets
            labels: Default labels

        Returns:
            Timer metric
        """
        with self._lock:
            if name in self._metrics:
                metric = self._metrics[name]
                if not isinstance(metric, Timer):
                    raise ValueError(f"Metric {name} exists but is not a Timer")
                return metric

            timer = Timer(name, description, buckets, labels)
            self._metrics[name] = timer
            return timer

    def get_metric(self, name: str) -> Optional[Metric]:
        """Get metric by name."""
        with self._lock:
            return self._metrics.get(name)

    def remove_metric(self, name: str) -> bool:
        """
        Remove metric from registry.

        Args:
            name: Metric name

        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if name in self._metrics:
                del self._metrics[name]
                return True
            return False

    def list_metrics(self) -> List[str]:
        """Get list of metric names."""
        with self._lock:
            return list(self._metrics.keys())

    def get_all_metrics(self) -> Dict[str, Metric]:
        """Get all metrics."""
        with self._lock:
            return dict(self._metrics)

    def collect_all(self) -> Dict[str, Any]:
        """
        Collect all metric values.

        Returns:
            Dictionary with all metric data
        """
        with self._lock:
            result = {}
            for name, metric in self._metrics.items():
                try:
                    result[name] = {
                        "info": metric.get_info(),
                        "value": metric.get_value()
                    }
                except Exception as e:
                    result[name] = {
                        "info": metric.get_info(),
                        "error": str(e)
                    }
            return result

    def reset_all(self) -> None:
        """Reset all metrics."""
        with self._lock:
            for metric in self._metrics.values():
                try:
                    metric.reset()
                except Exception:
                    pass  # Continue resetting other metrics

    def clear(self) -> None:
        """Clear all metrics from registry."""
        with self._lock:
            self._metrics.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        with self._lock:
            metric_types = defaultdict(int)
            for metric in self._metrics.values():
                metric_types[metric.metric_type.value] += 1

            return {
                "total_metrics": len(self._metrics),
                "metric_types": dict(metric_types),
                "metric_names": list(self._metrics.keys())
            }


# Add alias for compatibility
Registry = MetricsRegistry

# Global registry instance
_global_registry = MetricsRegistry()


def get_registry() -> MetricsRegistry:
    """Get the global metrics registry."""
    return _global_registry


# Convenience functions for global registry

def counter(name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Counter:
    """Get or create a counter from global registry."""
    return _global_registry.counter(name, description, labels)


def gauge(name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Gauge:
    """Get or create a gauge from global registry."""
    return _global_registry.gauge(name, description, labels)


def histogram(
    name: str,
    description: str = "",
    buckets: Optional[List[float]] = None,
    labels: Optional[Dict[str, str]] = None
) -> Histogram:
    """Get or create a histogram from global registry."""
    return _global_registry.histogram(name, description, buckets, labels)


def timer(
    name: str,
    description: str = "",
    buckets: Optional[List[float]] = None,
    labels: Optional[Dict[str, str]] = None
) -> Timer:
    """Get or create a timer from global registry."""
    return _global_registry.timer(name, description, buckets, labels)


# Export main classes and functions
__all__ = [
    "MetricsRegistry",
    "Registry",
    "Metric",
    "Counter",
    "Gauge",
    "Histogram",
    "Timer",
    "TimerContext",
    "MetricType",
    "MetricValue",
    "get_registry",
    "counter",
    "gauge",
    "histogram",
    "timer"
]