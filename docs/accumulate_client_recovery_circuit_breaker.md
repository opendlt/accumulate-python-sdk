# accumulate_client.recovery.circuit_breaker


Circuit breaker pattern for fault tolerance.

Provides automatic failure detection and service protection
with configurable thresholds, timeouts, and recovery strategies.


## Functions

### circuit_breaker(name: Optional[str] = None, config: Optional[accumulate_client.recovery.circuit_breaker.CircuitBreakerConfig] = None)


Decorator for wrapping functions with circuit breaker.

Args:
    name: Circuit breaker name (defaults to function name)
    config: Optional circuit breaker configuration

Returns:
    Decorator function


### create_api_circuit_breaker(name: str) -> accumulate_client.recovery.circuit_breaker.CircuitBreaker

Create circuit breaker optimized for API operations.

### create_database_circuit_breaker(name: str) -> accumulate_client.recovery.circuit_breaker.CircuitBreaker

Create circuit breaker optimized for database operations.

### create_network_circuit_breaker(name: str) -> accumulate_client.recovery.circuit_breaker.CircuitBreaker

Create circuit breaker optimized for network operations.

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


### get_circuit(name: str, config: Optional[accumulate_client.recovery.circuit_breaker.CircuitBreakerConfig] = None) -> accumulate_client.recovery.circuit_breaker.CircuitBreaker

Get circuit breaker from global registry.

## Classes

### Any

Special type indicating an unconstrained type.

- Any is compatible with every type.
- Any assumed to have all methods.
- All values assumed to be instances of Any.

Note that all the above statements are true from the point of view of
static type checkers. At runtime, Any should not be used with instance
checks.


### CallResult

Result of a function call through circuit breaker.

### CircuitBreaker


Circuit breaker implementation for fault tolerance.

Implements the circuit breaker pattern to prevent cascading failures
by monitoring operation success/failure rates and automatically
opening the circuit when thresholds are exceeded.

Features:
- Configurable failure and success thresholds
- Rolling window for failure rate calculation
- Slow call detection and rate monitoring
- Automatic recovery testing in half-open state
- Comprehensive metrics and monitoring


#### Methods

- **call(self, func: Callable, *args, **kwargs) -> Any**: 
- **force_closed(self)**: Force circuit to closed state.
- **force_half_open(self)**: Force circuit to half-open state.
- **force_open(self)**: Force circuit to open state.
- **get_metrics(self) -> Dict[str, Any]**: Get circuit breaker metrics.
- **reset(self)**: Reset circuit breaker to initial state.

### CircuitBreakerConfig

Configuration for circuit breaker.

### CircuitBreakerError

Circuit breaker operation error.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### CircuitBreakerRegistry


Registry for managing multiple circuit breakers.

Provides centralized management of circuit breakers with
global monitoring and configuration capabilities.


#### Methods

- **get_all_metrics(self) -> Dict[str, Dict[str, Any]]**: Get metrics for all circuit breakers.
- **get_circuit(self, name: str, config: Optional[accumulate_client.recovery.circuit_breaker.CircuitBreakerConfig] = None) -> accumulate_client.recovery.circuit_breaker.CircuitBreaker**: 
- **get_health_summary(self) -> Dict[str, Any]**: Get overall health summary.
- **get_open_circuits(self) -> List[str]**: Get list of open circuit breaker names.
- **list_circuits(self) -> List[str]**: Get list of circuit breaker names.
- **remove_circuit(self, name: str) -> bool**: 
- **reset_all(self)**: Reset all circuit breakers.

### CircuitOpenError

Circuit is open, rejecting requests.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### CircuitState

Circuit breaker states.

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

