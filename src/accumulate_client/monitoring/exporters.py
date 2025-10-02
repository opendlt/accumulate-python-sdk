"""
Metrics exporters for various output formats.

Provides exporters for JSON, Prometheus, logging, and other
formats to integrate with monitoring systems.
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, TextIO
import sys

from .metrics import MetricsRegistry, get_registry


logger = logging.getLogger(__name__)


class MetricsExporter(ABC):
    """Abstract base class for metrics exporters."""

    @abstractmethod
    def export(self, registry: MetricsRegistry) -> str:
        """
        Export metrics from registry.

        Args:
            registry: Metrics registry to export

        Returns:
            Exported metrics as string
        """
        pass


class JsonExporter(MetricsExporter):
    """JSON format metrics exporter."""

    def __init__(self, indent: Optional[int] = 2, include_timestamp: bool = True):
        """
        Initialize JSON exporter.

        Args:
            indent: JSON indentation (None for compact)
            include_timestamp: Whether to include export timestamp
        """
        self.indent = indent
        self.include_timestamp = include_timestamp

    def export(self, registry: MetricsRegistry) -> str:
        """Export metrics as JSON."""
        data = registry.collect_all()

        if self.include_timestamp:
            data["_export_timestamp"] = time.time()
            data["_export_time_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        return json.dumps(data, indent=self.indent, default=str)


class PrometheusExporter(MetricsExporter):
    """Prometheus format metrics exporter."""

    def export(self, registry: MetricsRegistry) -> str:
        """Export metrics in Prometheus format."""
        lines = []

        for name, metric in registry.get_all_metrics().items():
            metric_info = metric.get_info()
            metric_type = metric_info["type"]

            # Add help and type comments
            if metric_info["description"]:
                lines.append(f"# HELP {name} {metric_info['description']}")
            lines.append(f"# TYPE {name} {self._prometheus_type(metric_type)}")

            try:
                value = metric.get_value()
                self._add_metric_lines(lines, name, metric_type, value)
            except Exception as e:
                logger.warning(f"Failed to export metric {name}: {e}")

        return "\n".join(lines) + "\n"

    def _prometheus_type(self, metric_type: str) -> str:
        """Convert metric type to Prometheus type."""
        mapping = {
            "counter": "counter",
            "gauge": "gauge",
            "histogram": "histogram",
            "timer": "histogram"
        }
        return mapping.get(metric_type, "gauge")

    def _add_metric_lines(self, lines: list, name: str, metric_type: str, value: Any):
        """Add metric lines for Prometheus format."""
        if metric_type in ["counter", "gauge"]:
            if isinstance(value, (int, float)):
                lines.append(f"{name} {value}")
            elif isinstance(value, dict):
                # Handle labeled metrics
                for label_key, label_value in value.items():
                    if isinstance(label_value, (int, float)):
                        labels = self._parse_label_key(label_key)
                        label_str = self._format_labels(labels)
                        lines.append(f"{name}{label_str} {label_value}")

        elif metric_type in ["histogram", "timer"]:
            if isinstance(value, dict):
                self._add_histogram_lines(lines, name, value)

    def _add_histogram_lines(self, lines: list, name: str, histogram_data: dict):
        """Add histogram metric lines."""
        if "buckets" in histogram_data:
            # Add bucket lines
            for bucket, count in histogram_data["buckets"].items():
                if bucket == float('inf'):
                    lines.append(f"{name}_bucket{{le=\"+Inf\"}} {count}")
                else:
                    lines.append(f"{name}_bucket{{le=\"{bucket}\"}} {count}")

        if "count" in histogram_data:
            lines.append(f"{name}_count {histogram_data['count']}")

        if "sum" in histogram_data:
            lines.append(f"{name}_sum {histogram_data['sum']}")

    def _parse_label_key(self, label_key: str) -> Dict[str, str]:
        """Parse label key back to labels dict."""
        if not label_key:
            return {}
        pairs = label_key.split("|")
        return dict(pair.split("=", 1) for pair in pairs if "=" in pair)

    def _format_labels(self, labels: Dict[str, str]) -> str:
        """Format labels for Prometheus."""
        if not labels:
            return ""

        label_pairs = [f'{k}="{v}"' for k, v in sorted(labels.items())]
        return "{" + ",".join(label_pairs) + "}"


class LoggingExporter(MetricsExporter):
    """Logging-based metrics exporter."""

    def __init__(self, logger_name: str = "metrics", level: int = logging.INFO):
        """
        Initialize logging exporter.

        Args:
            logger_name: Logger name to use
            level: Logging level
        """
        self.logger = logging.getLogger(logger_name)
        self.level = level

    def export(self, registry: MetricsRegistry) -> str:
        """Export metrics to logger."""
        data = registry.collect_all()

        # Log summary
        stats = registry.get_stats()
        self.logger.log(self.level, f"Metrics export: {stats['total_metrics']} metrics")

        # Log individual metrics
        for name, metric_data in data.items():
            try:
                value = metric_data.get("value", "N/A")
                metric_type = metric_data.get("info", {}).get("type", "unknown")
                self.logger.log(self.level, f"Metric {name} ({metric_type}): {value}")
            except Exception as e:
                self.logger.warning(f"Failed to log metric {name}: {e}")

        return f"Exported {len(data)} metrics to logger"


class FileExporter(MetricsExporter):
    """File-based metrics exporter."""

    def __init__(self, file_path: str, format_exporter: MetricsExporter):
        """
        Initialize file exporter.

        Args:
            file_path: Output file path
            format_exporter: Exporter for format (JSON, Prometheus, etc.)
        """
        self.file_path = file_path
        self.format_exporter = format_exporter

    def export(self, registry: MetricsRegistry) -> str:
        """Export metrics to file."""
        content = self.format_exporter.export(registry)

        with open(self.file_path, 'w') as f:
            f.write(content)

        return f"Exported metrics to {self.file_path}"


class HttpExporter(MetricsExporter):
    """HTTP endpoint metrics exporter."""

    def __init__(self, format_exporter: MetricsExporter, content_type: str = "application/json"):
        """
        Initialize HTTP exporter.

        Args:
            format_exporter: Exporter for format
            content_type: HTTP content type
        """
        self.format_exporter = format_exporter
        self.content_type = content_type

    def export(self, registry: MetricsRegistry) -> str:
        """Export metrics for HTTP response."""
        return self.format_exporter.export(registry)

    def get_content_type(self) -> str:
        """Get HTTP content type."""
        return self.content_type


# Factory functions

def create_json_exporter(pretty: bool = True) -> JsonExporter:
    """Create JSON exporter."""
    return JsonExporter(indent=2 if pretty else None)

def create_prometheus_exporter() -> PrometheusExporter:
    """Create Prometheus exporter."""
    return PrometheusExporter()

def create_logging_exporter(level: str = "INFO") -> LoggingExporter:
    """Create logging exporter."""
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR
    }
    return LoggingExporter(level=level_map.get(level.upper(), logging.INFO))