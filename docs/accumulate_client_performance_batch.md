# accumulate_client.performance.batch


Request batching for improved throughput.

Provides automatic request batching with configurable timing,
size limits, and parallel execution for optimal performance.


## Functions

### create_high_throughput_batch_client(endpoint: str, pool: accumulate_client.performance.pool.HttpConnectionPool) -> accumulate_client.performance.batch.BatchClient

Create batch client optimized for high throughput.

### create_low_latency_batch_client(endpoint: str, pool: accumulate_client.performance.pool.HttpConnectionPool) -> accumulate_client.performance.batch.BatchClient

Create batch client optimized for low latency.

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


### uuid4()

Generate a random UUID.

## Classes

### Any

Special type indicating an unconstrained type.

- Any is compatible with every type.
- Any assumed to have all methods.
- All values assumed to be instances of Any.

Note that all the above statements are true from the point of view of
static type checkers. At runtime, Any should not be used with instance
checks.


### BatchClient


High-performance batching client for JSON-RPC requests.

Features:
- Automatic request batching with configurable triggers
- Priority-based request ordering
- Parallel batch execution
- Request deduplication
- Comprehensive error handling and retry logic


#### Methods

- **get_stats(self) -> Dict[str, Any]**: Get batch client statistics.
- **start(self)**: Start the batch processing.
- **stop(self, timeout: float = 30.0)**: 
- **submit(self, method: str, params: Dict[str, Any], priority: int = 0, timeout: float = 30.0) -> Any**: 
- **submit_many(self, requests: List[Dict[str, Any]], timeout: float = 30.0) -> List[Any]**: 
- **wait_for_completion(self, timeout: float = 30.0)**: Wait for all pending requests to complete.

### BatchError

Base batch error.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### BatchRequest

Individual request in a batch.

### BatchResponse

Response for a batch request.

### BatchTimeout

Batch operation timed out.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### HttpConnectionPool


High-performance HTTP connection pool with health monitoring.

Features:
- Persistent connections with configurable limits
- Automatic health checking and stale connection cleanup
- Per-host connection limits
- Request timeout and retry handling
- Connection statistics and monitoring


#### Methods

- **close(self)**: Close all connections and cleanup resources.
- **delete(self, url: str, **kwargs) -> 'aiohttp.ClientResponse'**: Make DELETE request.
- **get(self, url: str, **kwargs) -> 'aiohttp.ClientResponse'**: Make GET request.
- **get_active_connections(self) -> int**: Get number of active connections.
- **get_stats(self) -> Dict[str, Dict[str, Any]]**: 
- **post(self, url: str, **kwargs) -> 'aiohttp.ClientResponse'**: Make POST request.
- **put(self, url: str, **kwargs) -> 'aiohttp.ClientResponse'**: Make PUT request.
- **request(self, method: str, url: str, **kwargs) -> 'aiohttp.ClientResponse'**: 
- **start(self)**: Start the connection pool.
- **warm_up(self, urls: List[str])**: 

### JsonRpcClient

JSON-RPC 2.0 client

#### Methods

- **batch(self, requests_list: List[Dict[str, Any]]) -> List[Any]**: Make a batch JSON-RPC call
- **call(self, method: str, params: Any = None) -> Any**: Make a JSON-RPC call
- **close(self) -> None**: Close the HTTP session

