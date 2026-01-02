# accumulate_client.monitoring.metrics


Metrics collection and registry for telemetry.

Provides thread-safe metrics collection with counters, gauges,
histograms, and timers for comprehensive observability.


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


### counter(name: str, description: str = '', labels: Optional[Dict[str, str]] = None) -> accumulate_client.monitoring.metrics.Counter

Get or create a counter from global registry.

### dataclass(cls=None, /, *, init=True, repr=True, eq=True, order=False, unsafe_hash=False, frozen=False, match_args=True, kw_only=False, slots=False, weakref_slot=False)

Add dunder methods based on the fields defined in the class.

Examines PEP 526 __annotations__ to determine fields.

If init is true, an __init__() method is added to the class. If repr
is true, a __repr__() method is added. If order is true, rich
comparison dunder methods are added. If unsafe_hash is true, a
__hash__() method is added. If frozen is true, fields may not be
assigned to after instance creation. If match_args is true, the
__match_args__ tuple is added. If kw_only is true, then by default
all fields are keyword-only. If slots is true, a new class with a
__slots__ attribute is returned.


### field(*, default=<dataclasses._MISSING_TYPE object at 0x000002B51A680590>, default_factory=<dataclasses._MISSING_TYPE object at 0x000002B51A680590>, init=True, repr=True, hash=None, compare=True, metadata=None, kw_only=<dataclasses._MISSING_TYPE object at 0x000002B51A680590>)

Return an object to identify dataclass fields.

default is the default value of the field.  default_factory is a
0-argument function called to initialize a field's value.  If init
is true, the field will be a parameter to the class's __init__()
function.  If repr is true, the field will be included in the
object's repr().  If hash is true, the field will be included in the
object's hash().  If compare is true, the field will be used in
comparison functions.  metadata, if specified, must be a mapping
which is stored but not otherwise examined by dataclass.  If kw_only
is true, the field will become a keyword-only parameter to
__init__().

It is an error to specify both default and default_factory.


### gauge(name: str, description: str = '', labels: Optional[Dict[str, str]] = None) -> accumulate_client.monitoring.metrics.Gauge

Get or create a gauge from global registry.

### get_registry() -> accumulate_client.monitoring.metrics.MetricsRegistry

Get the global metrics registry.

### histogram(name: str, description: str = '', buckets: Optional[List[float]] = None, labels: Optional[Dict[str, str]] = None) -> accumulate_client.monitoring.metrics.Histogram

Get or create a histogram from global registry.

### timer(name: str, description: str = '', buckets: Optional[List[float]] = None, labels: Optional[Dict[str, str]] = None) -> accumulate_client.monitoring.metrics.Timer

Get or create a timer from global registry.

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

### Enum


Create a collection of name/value pairs.

Example enumeration:

>>> class Color(Enum):
...     RED = 1
...     BLUE = 2
...     GREEN = 3

Access them by:

- attribute access:

  >>> Color.RED
  <Color.RED: 1>

- value lookup:

  >>> Color(1)
  <Color.RED: 1>

- name lookup:

  >>> Color['RED']
  <Color.RED: 1>

Enumerations can be iterated over, and know how many members they have:

>>> len(Color)
3

>>> list(Color)
[<Color.RED: 1>, <Color.BLUE: 2>, <Color.GREEN: 3>]

Methods can be added to enumerations, and members can have their own
attributes -- see the documentation for details.


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

### Histogram


Histogram metric for tracking distributions.

Thread-safe histogram with configurable buckets for tracking
distributions of values like request durations or response sizes.


#### Methods

- **get_all_values(self) -> Dict[str, Dict[str, Any]]**: Get all histogram values by label combination.
- **get_info(self) -> Dict[str, Any]**: Get metric information.
- **get_value(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]**: Get histogram statistics.
- **observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None**: 
- **reset(self) -> None**: Reset histogram.

### Metric


Abstract base class for metrics.

Defines the interface for all metric types with thread-safe
operations and label support.


#### Methods

- **get_info(self) -> Dict[str, Any]**: Get metric information.
- **get_value(self, labels: Optional[Dict[str, str]] = None) -> Union[int, float, Dict[str, Any]]**: Get current metric value.
- **reset(self) -> None**: Reset metric to initial state.

### MetricType

Types of metrics.

### MetricValue

Value of a metric at a point in time.

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

### TimerContext

Context manager for timing operations.

### defaultdict

defaultdict(default_factory=None, /, [...]) --> dict with default factory

The default factory is called without arguments to produce
a new value when a key is not present, in __getitem__ only.
A defaultdict compares equal to a dict with the same items.
All remaining arguments are treated the same as if they were
passed to the dict constructor, including keyword arguments.


#### Methods

- **clear(self, /)**: Remove all items from the dict.
- **copy(self, /)**: D.copy() -> a shallow copy of D.
- **fromkeys(iterable, value=None, /)**: Create a new dictionary with keys from iterable and values set to value.
- **get(self, key, default=None, /)**: Return the value for key if key is in the dictionary, else default.
- **items(self, /)**: Return a set-like object providing a view on the dict's items.
- **keys(self, /)**: Return a set-like object providing a view on the dict's keys.
- **pop(...)**: D.pop(k[,d]) -> v, remove specified key and return the corresponding value.
- **popitem(self, /)**: Remove and return a (key, value) pair as a 2-tuple.
- **setdefault(self, key, default=None, /)**: Insert key with a value of default if key is not in the dictionary.
- **update(...)**: D.update([E, ]**F) -> None.  Update D from mapping/iterable E and F.
- **values(self, /)**: Return an object providing a view on the dict's values.

### deque

A list-like sequence optimized for data accesses near its endpoints.

#### Methods

- **append(self, item, /)**: Add an element to the right side of the deque.
- **appendleft(self, item, /)**: Add an element to the left side of the deque.
- **clear(self, /)**: Remove all elements from the deque.
- **copy(self, /)**: Return a shallow copy of a deque.
- **count(self, value, /)**: Return number of occurrences of value.
- **extend(self, iterable, /)**: Extend the right side of the deque with elements from the iterable.
- **extendleft(self, iterable, /)**: Extend the left side of the deque with elements from the iterable.
- **index(...)**: Return first index of value.
- **insert(self, index, value, /)**: Insert value before index.
- **pop(self, /)**: Remove and return the rightmost element.
- **popleft(self, /)**: Remove and return the leftmost element.
- **remove(self, value, /)**: Remove first occurrence of value.
- **reverse(self, /)**: Reverse *IN PLACE*.
- **rotate(self, n=1, /)**: Rotate the deque n steps to the right.  If n is negative, rotates left.

