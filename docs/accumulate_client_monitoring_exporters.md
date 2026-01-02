# accumulate_client.monitoring.exporters


Metrics exporters for various output formats.

Provides exporters for JSON, Prometheus, logging, and other
formats to integrate with monitoring systems.


## Functions

### abstractmethod(funcobj)

A decorator indicating abstract methods.

Requires that the metaclass is ABCMeta or derived from it.  A
class that has a metaclass derived from ABCMeta cannot be
instantiated unless all of its abstract methods are overridden.
The abstract methods can be called using any of the normal
'super' call mechanisms.  abstractmethod() may be used to declare
abstract methods for properties and descriptors.

Usage:

    class C(metaclass=ABCMeta):
        @abstractmethod
        def my_abstract_method(self, arg1, arg2, argN):
            ...


### create_json_exporter(pretty: bool = True) -> accumulate_client.monitoring.exporters.JsonExporter

Create JSON exporter.

### create_logging_exporter(level: str = 'INFO') -> accumulate_client.monitoring.exporters.LoggingExporter

Create logging exporter.

### create_prometheus_exporter() -> accumulate_client.monitoring.exporters.PrometheusExporter

Create Prometheus exporter.

### get_registry() -> accumulate_client.monitoring.metrics.MetricsRegistry

Get the global metrics registry.

## Classes

### ABC

Helper class that provides a standard way to create an ABC using
inheritance.


### Any

Special type indicating an unconstrained type.

- Any is compatible with every type.
- Any assumed to have all methods.
- All values assumed to be instances of Any.

Note that all the above statements are true from the point of view of
static type checkers. At runtime, Any should not be used with instance
checks.


### FileExporter

File-based metrics exporter.

#### Methods

- **export(self, registry: accumulate_client.monitoring.metrics.MetricsRegistry) -> str**: Export metrics to file.

### HttpExporter

HTTP endpoint metrics exporter.

#### Methods

- **export(self, registry: accumulate_client.monitoring.metrics.MetricsRegistry) -> str**: Export metrics for HTTP response.
- **get_content_type(self) -> str**: Get HTTP content type.

### JsonExporter

JSON format metrics exporter.

#### Methods

- **export(self, registry: accumulate_client.monitoring.metrics.MetricsRegistry) -> str**: Export metrics as JSON.

### LoggingExporter

Logging-based metrics exporter.

#### Methods

- **export(self, registry: accumulate_client.monitoring.metrics.MetricsRegistry) -> str**: Export metrics to logger.

### MetricsExporter

Abstract base class for metrics exporters.

#### Methods

- **export(self, registry: accumulate_client.monitoring.metrics.MetricsRegistry) -> str**: 

### MetricsRegistry


Registry for managing metrics.

Thread-safe registry that maintains all metrics and provides
utilities for creation, retrieval, and bulk operations.


#### Methods

- **clear(self) -> None**: Clear all metrics from registry.
- **collect_all(self) -> Dict[str, Any]**: 
- **counter(self, name: str, description: str = '', labels: Optional[Dict[str, str]] = None) -> accumulate_client.monitoring.metrics.Counter**: 
- **gauge(self, name: str, description: str = '', labels: Optional[Dict[str, str]] = None) -> accumulate_client.monitoring.metrics.Gauge**: 
- **get_all_metrics(self) -> Dict[str, accumulate_client.monitoring.metrics.Metric]**: Get all metrics.
- **get_metric(self, name: str) -> Optional[accumulate_client.monitoring.metrics.Metric]**: Get metric by name.
- **get_stats(self) -> Dict[str, Any]**: Get registry statistics.
- **histogram(self, name: str, description: str = '', buckets: Optional[List[float]] = None, labels: Optional[Dict[str, str]] = None) -> accumulate_client.monitoring.metrics.Histogram**: 
- **list_metrics(self) -> List[str]**: Get list of metric names.
- **remove_metric(self, name: str) -> bool**: 
- **reset_all(self) -> None**: Reset all metrics.
- **timer(self, name: str, description: str = '', buckets: Optional[List[float]] = None, labels: Optional[Dict[str, str]] = None) -> accumulate_client.monitoring.metrics.Timer**: 

### PrometheusExporter

Prometheus format metrics exporter.

#### Methods

- **export(self, registry: accumulate_client.monitoring.metrics.MetricsRegistry) -> str**: Export metrics in Prometheus format.

### TextIO

Typed version of the return of open() in text mode.

#### Methods

- **close(self) -> None**
- **fileno(self) -> int**
- **flush(self) -> None**
- **isatty(self) -> bool**
- **read(self, n: int = -1) -> ~AnyStr**
- **readable(self) -> bool**
- **readline(self, limit: int = -1) -> ~AnyStr**
- **readlines(self, hint: int = -1) -> List[~AnyStr]**
- **seek(self, offset: int, whence: int = 0) -> int**
- **seekable(self) -> bool**
- **tell(self) -> int**
- **truncate(self, size: int = None) -> int**
- **writable(self) -> bool**
- **write(self, s: ~AnyStr) -> int**
- **writelines(self, lines: List[~AnyStr]) -> None**

