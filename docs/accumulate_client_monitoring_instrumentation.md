# accumulate_client.monitoring.instrumentation


Instrumentation for automatic metrics collection.

Provides decorators and utilities for instrumenting clients,
functions, and system resources with automatic metrics.


## Functions

### auto_instrument(client, collect_system: bool = True, system_interval: float = 60.0) -> Dict[str, Any]


Automatically instrument client and optionally collect system metrics.

Args:
    client: AccumulateClient instance
    collect_system: Whether to collect system metrics
    system_interval: System metrics collection interval

Returns:
    Dictionary with instrumentation objects


### collect_system_metrics(prefix: str = 'system') -> Dict[str, Any]


Collect system metrics and update registry.

Args:
    prefix: Metric name prefix

Returns:
    Dictionary of collected metrics


### create_metrics_summary() -> Dict[str, Any]

Create summary of all collected metrics.

### get_registry() -> accumulate_client.monitoring.metrics.MetricsRegistry

Get the global metrics registry.

### instrument_client(client, prefix: str = 'accumulate_client') -> accumulate_client.monitoring.instrumentation.ClientInstrumentation


Instrument an AccumulateClient with automatic metrics.

Args:
    client: AccumulateClient instance
    prefix: Metric name prefix

Returns:
    ClientInstrumentation instance


### instrument_function(name: Optional[str] = None, labels: Optional[Dict[str, str]] = None, include_args: bool = False, include_result: bool = False)


Decorator to instrument function calls with metrics.

Args:
    name: Metric name prefix (defaults to function name)
    labels: Additional labels for metrics
    include_args: Whether to include function arguments in labels
    include_result: Whether to track result types

Returns:
    Decorated function


## Classes

### Any

Special type indicating an unconstrained type.

- Any is compatible with every type.
- Any assumed to have all methods.
- All values assumed to be instances of Any.

Note that all the above statements are true from the point of view of
static type checkers. At runtime, Any should not be used with instance
checks.


### ClientInstrumentation

Instrumentation wrapper for AccumulateClient.

### Counter


Counter metric that only increases.

Thread-safe counter with label support for tracking
cumulative values like request counts or error rates.


#### Methods

- **get_all_values(self) -> Dict[str, float]**: Get all counter values by label combination.
- **get_info(self) -> Dict[str, Any]**: Get metric information.
- **get_value(self, labels: Optional[Dict[str, str]] = None) -> float**: Get counter value.
- **increment(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None**: 
- **reset(self) -> None**: Reset counter.

### Gauge


Gauge metric that can increase or decrease.

Thread-safe gauge with label support for tracking
current values like active connections or memory usage.


#### Methods

- **decrement(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None**: 
- **get_all_values(self) -> Dict[str, float]**: Get all gauge values by label combination.
- **get_info(self) -> Dict[str, Any]**: Get metric information.
- **get_value(self, labels: Optional[Dict[str, str]] = None) -> float**: Get gauge value.
- **increment(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None**: 
- **reset(self) -> None**: Reset gauge.
- **set(self, value: float, labels: Optional[Dict[str, str]] = None) -> None**: 

### SystemMetricsCollector

Background system metrics collector.

#### Methods

- **start(self)**: Start metrics collection.
- **stop(self)**: Stop metrics collection.

### Timer


Timer metric for measuring durations.

Combines histogram for duration distribution with
counters for total time and operation counts.


#### Methods

- **get_info(self) -> Dict[str, Any]**: Get metric information.
- **get_value(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]**: Get timer statistics.
- **observe(self, duration: float, labels: Optional[Dict[str, str]] = None) -> None**: 
- **reset(self) -> None**: Reset timer.
- **time(self, labels: Optional[Dict[str, str]] = None)**: 

