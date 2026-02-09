"""
Instrumentation for automatic metrics collection.

Provides decorators and utilities for instrumenting clients,
functions, and system resources with automatic metrics.
"""

import asyncio
import functools
import logging
import time
from typing import Any, Callable, Dict, Optional, Union

from .metrics import get_registry, Counter, Timer, Gauge


logger = logging.getLogger(__name__)


def instrument_function(
    name: Optional[str] = None,
    labels: Optional[Dict[str, str]] = None,
    include_args: bool = False,
    include_result: bool = False
):
    """
    Decorator to instrument function calls with metrics.

    Args:
        name: Metric name prefix (defaults to function name)
        labels: Additional labels for metrics
        include_args: Whether to include function arguments in labels
        include_result: Whether to track result types

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        metric_name = name or f"{func.__module__}.{func.__qualname__}"
        registry = get_registry()

        # Create metrics
        call_timer = registry.timer(f"{metric_name}_duration", f"Duration of {metric_name} calls")
        call_counter = registry.counter(f"{metric_name}_calls", f"Total {metric_name} calls")
        error_counter = registry.counter(f"{metric_name}_errors", f"Total {metric_name} errors")

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            metric_labels = (labels or {}).copy()

            # Add argument information if requested
            if include_args and args:
                metric_labels["args_count"] = str(len(args))

            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                # Track result type if requested
                if include_result:
                    metric_labels["result_type"] = type(result).__name__

                duration = time.time() - start_time
                call_timer.observe(duration, metric_labels)
                call_counter.increment(1, metric_labels)

                return result

            except Exception as e:
                error_labels = metric_labels.copy()
                error_labels["error_type"] = type(e).__name__
                error_counter.increment(1, error_labels)
                raise

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            metric_labels = (labels or {}).copy()

            if include_args and args:
                metric_labels["args_count"] = str(len(args))

            try:
                result = func(*args, **kwargs)

                if include_result:
                    metric_labels["result_type"] = type(result).__name__

                duration = time.time() - start_time
                call_timer.observe(duration, metric_labels)
                call_counter.increment(1, metric_labels)

                return result

            except Exception as e:
                error_labels = metric_labels.copy()
                error_labels["error_type"] = type(e).__name__
                error_counter.increment(1, error_labels)
                raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


class ClientInstrumentation:
    """Instrumentation wrapper for AccumulateClient."""

    def __init__(self, client, prefix: str = "accumulate_client"):
        """
        Initialize client instrumentation.

        Args:
            client: AccumulateClient instance
            prefix: Metric name prefix
        """
        self.client = client
        self.prefix = prefix
        self.registry = get_registry()

        # Create metrics
        self.request_timer = self.registry.timer(
            f"{prefix}_request_duration",
            "Duration of client requests"
        )
        self.request_counter = self.registry.counter(
            f"{prefix}_requests_total",
            "Total client requests"
        )
        self.error_counter = self.registry.counter(
            f"{prefix}_errors_total",
            "Total client errors"
        )
        self.active_requests = self.registry.gauge(
            f"{prefix}_active_requests",
            "Currently active requests"
        )

        # Instrument the client
        self._instrument_client()

    def _instrument_client(self):
        """Add instrumentation to client methods."""
        # List of methods to instrument
        methods_to_instrument = [
            'call', 'submit', 'query', 'query_tx', 'query_directory',
            'faucet', 'metrics', 'version', 'status'
        ]

        for method_name in methods_to_instrument:
            if hasattr(self.client, method_name):
                original_method = getattr(self.client, method_name)
                instrumented_method = self._create_instrumented_method(
                    original_method, method_name
                )
                setattr(self.client, method_name, instrumented_method)

    def _create_instrumented_method(self, original_method: Callable, method_name: str) -> Callable:
        """Create instrumented version of a method."""
        @functools.wraps(original_method)
        async def async_instrumented(*args, **kwargs):
            labels = {"method": method_name}
            start_time = time.time()

            self.active_requests.increment(1, labels)
            self.request_counter.increment(1, labels)

            try:
                if asyncio.iscoroutinefunction(original_method):
                    result = await original_method(*args, **kwargs)
                else:
                    result = original_method(*args, **kwargs)

                duration = time.time() - start_time
                self.request_timer.observe(duration, labels)

                # Track success
                success_labels = labels.copy()
                success_labels["status"] = "success"
                self.request_counter.increment(1, success_labels)

                return result

            except Exception as e:
                # Track error
                error_labels = labels.copy()
                error_labels["error_type"] = type(e).__name__
                self.error_counter.increment(1, error_labels)
                raise

            finally:
                self.active_requests.decrement(1, labels)

        @functools.wraps(original_method)
        def sync_instrumented(*args, **kwargs):
            labels = {"method": method_name}
            start_time = time.time()

            self.active_requests.increment(1, labels)
            self.request_counter.increment(1, labels)

            try:
                result = original_method(*args, **kwargs)

                duration = time.time() - start_time
                self.request_timer.observe(duration, labels)

                success_labels = labels.copy()
                success_labels["status"] = "success"
                self.request_counter.increment(1, success_labels)

                return result

            except Exception as e:
                error_labels = labels.copy()
                error_labels["error_type"] = type(e).__name__
                self.error_counter.increment(1, error_labels)
                raise

            finally:
                self.active_requests.decrement(1, labels)

        if asyncio.iscoroutinefunction(original_method):
            return async_instrumented
        else:
            return sync_instrumented


def instrument_client(client, prefix: str = "accumulate_client") -> ClientInstrumentation:
    """
    Instrument an AccumulateClient with automatic metrics.

    Args:
        client: AccumulateClient instance
        prefix: Metric name prefix

    Returns:
        ClientInstrumentation instance
    """
    return ClientInstrumentation(client, prefix)


def collect_system_metrics(prefix: str = "system") -> Dict[str, Any]:
    """
    Collect system metrics and update registry.

    Args:
        prefix: Metric name prefix

    Returns:
        Dictionary of collected metrics
    """
    registry = get_registry()

    try:
        import psutil
    except ImportError:
        logger.warning("psutil not installed – install with: pip install psutil")
        return {"error": "psutil not installed", "timestamp": time.time()}

    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=None)
        cpu_gauge = registry.gauge(f"{prefix}_cpu_percent", "CPU usage percentage")
        cpu_gauge.set(cpu_percent)

        # Memory metrics
        memory = psutil.virtual_memory()
        memory_total = registry.gauge(f"{prefix}_memory_total_bytes", "Total memory in bytes")
        memory_used = registry.gauge(f"{prefix}_memory_used_bytes", "Used memory in bytes")
        memory_percent = registry.gauge(f"{prefix}_memory_percent", "Memory usage percentage")

        memory_total.set(memory.total)
        memory_used.set(memory.used)
        memory_percent.set(memory.percent)

        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_total = registry.gauge(f"{prefix}_disk_total_bytes", "Total disk space in bytes")
        disk_used = registry.gauge(f"{prefix}_disk_used_bytes", "Used disk space in bytes")
        disk_percent = registry.gauge(f"{prefix}_disk_percent", "Disk usage percentage")

        disk_total.set(disk.total)
        disk_used.set(disk.used)
        disk_percent.set((disk.used / disk.total) * 100)

        # Network metrics (if available)
        try:
            net_io = psutil.net_io_counters()
            bytes_sent = registry.counter(f"{prefix}_network_bytes_sent", "Network bytes sent")
            bytes_recv = registry.counter(f"{prefix}_network_bytes_received", "Network bytes received")

            # Note: This will keep incrementing the counter with absolute values
            # In practice, you'd want to track deltas
            bytes_sent.increment(net_io.bytes_sent - bytes_sent.get_value())
            bytes_recv.increment(net_io.bytes_recv - bytes_recv.get_value())

        except Exception:
            pass  # Network metrics not available

        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "disk_percent": (disk.used / disk.total) * 100,
            "timestamp": time.time()
        }

    except Exception as e:
        logger.warning(f"Failed to collect system metrics: {e}")
        return {"error": str(e), "timestamp": time.time()}


class SystemMetricsCollector:
    """Background system metrics collector."""

    def __init__(self, interval: float = 60.0, prefix: str = "system"):
        """
        Initialize system metrics collector.

        Args:
            interval: Collection interval in seconds
            prefix: Metric name prefix
        """
        self.interval = interval
        self.prefix = prefix
        self.running = False
        self.task: Optional[asyncio.Task] = None

    async def start(self):
        """Start metrics collection."""
        if self.running:
            return

        self.running = True
        self.task = asyncio.create_task(self._collection_loop())
        logger.info(f"Started system metrics collection (interval: {self.interval}s)")

    async def stop(self):
        """Stop metrics collection."""
        if not self.running:
            return

        self.running = False

        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        logger.info("Stopped system metrics collection")

    async def _collection_loop(self):
        """Background collection loop."""
        while self.running:
            try:
                collect_system_metrics(self.prefix)
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in system metrics collection: {e}")
                await asyncio.sleep(self.interval)


# Convenience functions

def auto_instrument(
    client,
    collect_system: bool = True,
    system_interval: float = 60.0
) -> Dict[str, Any]:
    """
    Automatically instrument client and optionally collect system metrics.

    Args:
        client: AccumulateClient instance
        collect_system: Whether to collect system metrics
        system_interval: System metrics collection interval

    Returns:
        Dictionary with instrumentation objects
    """
    result = {}

    # Instrument client
    client_instrumentation = instrument_client(client)
    result["client_instrumentation"] = client_instrumentation

    # Setup system metrics if requested
    if collect_system:
        system_collector = SystemMetricsCollector(system_interval)
        result["system_collector"] = system_collector

        # Start system collection in background
        try:
            asyncio.create_task(system_collector.start())
        except RuntimeError:
            # No event loop running
            logger.warning("No event loop available for system metrics collection")

    logger.info("Auto-instrumentation completed")
    return result


def create_metrics_summary() -> Dict[str, Any]:
    """Create summary of all collected metrics."""
    registry = get_registry()

    summary = {
        "timestamp": time.time(),
        "registry_stats": registry.get_stats(),
        "metrics": {}
    }

    try:
        all_metrics = registry.collect_all()
        for name, data in all_metrics.items():
            summary["metrics"][name] = {
                "type": data.get("info", {}).get("type", "unknown"),
                "value": data.get("value", "N/A")
            }
    except Exception as e:
        summary["error"] = str(e)

    return summary