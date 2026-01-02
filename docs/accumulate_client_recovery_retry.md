# accumulate_client.recovery.retry


Retry policies for robust error handling.

Provides configurable retry strategies with backoff algorithms,
jitter, and condition-based retry logic for different failure modes.


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


### create_api_retry_policy() -> accumulate_client.recovery.retry.RetryPolicy

Create retry policy optimized for API calls.

### create_network_retry_policy() -> accumulate_client.recovery.retry.RetryPolicy

Create retry policy optimized for network operations.

### create_transaction_retry_policy() -> accumulate_client.recovery.retry.RetryPolicy

Create retry policy optimized for transaction operations.

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


### retry_on_exception(func: Callable, exceptions: Tuple[Type[Exception], ...], max_attempts: int = 3, base_delay: float = 1.0, strategy: accumulate_client.recovery.retry.RetryStrategy = <RetryStrategy.EXPONENTIAL: 'exponential'>, *args, **kwargs) -> Any


Retry function execution on specific exceptions.

Args:
    func: Function to execute
    exceptions: Tuple of exception types to retry on
    max_attempts: Maximum retry attempts
    base_delay: Base delay between retries
    strategy: Retry strategy
    *args: Function arguments
    **kwargs: Function keyword arguments

Returns:
    Function result


### with_retry(max_attempts: int = 3, base_delay: float = 1.0, strategy: accumulate_client.recovery.retry.RetryStrategy = <RetryStrategy.EXPONENTIAL: 'exponential'>, **kwargs)


Decorator for adding retry behavior to functions.

Args:
    max_attempts: Maximum retry attempts
    base_delay: Base delay between retries
    strategy: Retry strategy
    **kwargs: Additional policy parameters

Returns:
    Decorator function


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


### ConditionalRetryPolicy


Retry policy with custom retry conditions.

Allows specification of custom conditions for determining
whether to retry based on exception type and content.


#### Methods

- **add_jitter(self, delay: float) -> float**: 
- **calculate_delay(self, attempt: int) -> float**: Calculate delay based on strategy.
- **execute(self, func: Callable, *args, **kwargs) -> Any**: 
- **get_stats(self) -> dict**: Get retry policy statistics.
- **should_retry(self, attempt: int, exception: Exception) -> bool**: Enhanced retry condition checking.

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


### ExponentialBackoff


Exponential backoff retry policy.

Delay increases exponentially with each attempt: base_delay * (factor ^ attempt)


#### Methods

- **add_jitter(self, delay: float) -> float**: 
- **calculate_delay(self, attempt: int) -> float**: Calculate exponential backoff delay.
- **execute(self, func: Callable, *args, **kwargs) -> Any**: 
- **get_stats(self) -> dict**: Get retry policy statistics.
- **should_retry(self, attempt: int, exception: Exception) -> bool**: 

### FixedBackoff


Fixed delay retry policy.

Uses constant delay between all retry attempts.


#### Methods

- **add_jitter(self, delay: float) -> float**: 
- **calculate_delay(self, attempt: int) -> float**: Calculate fixed delay.
- **execute(self, func: Callable, *args, **kwargs) -> Any**: 
- **get_stats(self) -> dict**: Get retry policy statistics.
- **should_retry(self, attempt: int, exception: Exception) -> bool**: 

### LinearBackoff


Linear backoff retry policy.

Delay increases linearly with each attempt: base_delay + (increment * attempt)


#### Methods

- **add_jitter(self, delay: float) -> float**: 
- **calculate_delay(self, attempt: int) -> float**: Calculate linear backoff delay.
- **execute(self, func: Callable, *args, **kwargs) -> Any**: 
- **get_stats(self) -> dict**: Get retry policy statistics.
- **should_retry(self, attempt: int, exception: Exception) -> bool**: 

### MaxRetriesExceeded

Maximum retry attempts exceeded.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### RetryAttempt

Information about a retry attempt.

### RetryError

Retry operation failed.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### RetryPolicy


Abstract base class for retry policies.

Defines the interface for retry strategies with configurable
backoff algorithms and retry conditions.


#### Methods

- **add_jitter(self, delay: float) -> float**: 
- **calculate_delay(self, attempt: int) -> float**: 
- **execute(self, func: Callable, *args, **kwargs) -> Any**: 
- **get_stats(self) -> dict**: Get retry policy statistics.
- **should_retry(self, attempt: int, exception: Exception) -> bool**: 

### RetryStrategy

Retry strategy types.

