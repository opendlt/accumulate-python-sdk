# accumulate_client.performance.pipeline


Pipeline transaction submission for maximum throughput.

Provides high-performance transaction pipeline with parallel signing,
submission, and status tracking for optimal transaction processing.


## Functions

### create_high_throughput_pipeline(client: accumulate_client.api_client.AccumulateClient, pool: accumulate_client.performance.pool.HttpConnectionPool, batch_client: accumulate_client.performance.batch.BatchClient) -> accumulate_client.performance.pipeline.PipelineClient

Create pipeline optimized for high throughput.

### create_low_latency_pipeline(client: accumulate_client.api_client.AccumulateClient, pool: accumulate_client.performance.pool.HttpConnectionPool) -> accumulate_client.performance.pipeline.PipelineClient

Create pipeline optimized for low latency.

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

### AccumulateClient


Enhanced Accumulate API Client

Provides complete implementation of all 35 Accumulate API methods with:
- Proper parameter handling and validation
- Automatic retries with exponential backoff
- Comprehensive error handling
- SSL/TLS support
- Response validation
- Debug logging


#### Methods

- **consensus_status(self, node_id: 'Optional[str]' = None, partition: 'Optional[str]' = None, include_peers: 'Optional[bool]' = None, include_accumulate: 'Optional[bool]' = None) -> 'Dict[str, Any]'**: 
- **describe(self) -> 'DescriptionResponse'**: 
- **execute(self, envelope: 'Dict[str, Any]', check_only: 'Optional[bool]' = None) -> 'Dict[str, Any]'**: 
- **execute_direct(self, envelope: 'Dict[str, Any]', check_only: 'Optional[bool]' = None) -> 'Dict[str, Any]'**: 
- **execute_local(self, envelope: 'Dict[str, Any]', check_only: 'Optional[bool]' = None) -> 'Dict[str, Any]'**: 
- **faucet(self, account: 'Union[str, AccountUrl]', options: 'Optional[FaucetOptions]' = None) -> 'Dict[str, Any]'**: 
- **find_service(self, network: 'Optional[str]' = None, service: 'Optional[str]' = None, known: 'Optional[List[str]]' = None, timeout: 'Optional[float]' = None) -> 'List[Dict[str, Any]]'**: 
- **for_network(network: 'str', **kwargs) -> "'AccumulateClient'"**: 
- **list_snapshots(self, node_id: 'Optional[str]' = None, partition: 'Optional[str]' = None) -> 'List[Dict[str, Any]]'**: 
- **metrics(self, partition: 'Optional[str]' = None, span: 'Optional[str]' = None) -> 'Dict[str, Any]'**: 
- **network_status(self, partition: 'Optional[str]' = None) -> 'Dict[str, Any]'**: 
- **node_info(self, peer_id: 'Optional[str]' = None) -> 'Dict[str, Any]'**: 
- **query(self, scope: 'Union[str, AccountUrl]', query: 'Optional[Dict[str, Any]]' = None) -> 'Dict[str, Any]'**: 
- **query_account_as(self, account: 'str', as_of: 'Union[int, str]', **kwargs) -> 'Dict[str, Any]'**: 
- **query_anchor_search(self, anchor: 'str', include_receipt: 'bool' = True, **kwargs) -> 'Dict[str, Any]'**: 
- **query_chain(self, account: 'str', chain: 'str', **kwargs) -> 'Dict[str, Any]'**: 
- **query_data(self, url: 'Union[str, AccountUrl]', entry_hash: 'Optional[Union[str, bytes]]' = None, options: 'Optional[QueryOptions]' = None) -> 'Dict[str, Any]'**: 
- **query_data_set(self, url: 'Union[str, AccountUrl]', pagination: 'Optional[QueryPagination]' = None, options: 'Optional[QueryOptions]' = None) -> 'MultiResponse'**: 
- **query_delegate(self, account: 'str', **kwargs) -> 'Dict[str, Any]'**: 
- **query_directory(self, url: 'Union[str, AccountUrl]', pagination: 'Optional[QueryPagination]' = None, options: 'Optional[QueryOptions]' = None) -> 'MultiResponse'**: 
- **query_key_page_index(self, url: 'Union[str, AccountUrl]', key: 'Union[str, bytes]', options: 'Optional[QueryOptions]' = None) -> 'Dict[str, Any]'**: 
- **query_major_blocks(self, url: 'Union[str, AccountUrl]', pagination: 'Optional[QueryPagination]' = None, options: 'Optional[QueryOptions]' = None) -> 'MultiResponse'**: 
- **query_minor_blocks(self, url: 'Union[str, AccountUrl]', pagination: 'Optional[QueryPagination]' = None, tx_fetch_mode: 'Optional[str]' = None, block_filter_mode: 'Optional[str]' = None, options: 'Optional[QueryOptions]' = None) -> 'MultiResponse'**: 
- **query_public_key(self, public_key: 'str', **kwargs) -> 'Dict[str, Any]'**: 
- **query_public_key_hash(self, key_hash: 'str', **kwargs) -> 'Dict[str, Any]'**: 
- **query_signature(self, signature_hash: 'str', **kwargs) -> 'Dict[str, Any]'**: 
- **query_synth(self, source: 'Union[str, AccountUrl]', destination: 'Union[str, AccountUrl]', sequence_number: 'Optional[int]' = None, anchor: 'Optional[bool]' = None, options: 'Optional[QueryOptions]' = None) -> 'TransactionQueryResponse'**: 
- **query_tx(self, txid: 'Union[str, bytes]', wait: 'Optional[float]' = None, ignore_pending: 'Optional[bool]' = None, options: 'Optional[QueryOptions]' = None) -> 'TransactionQueryResponse'**: 
- **query_tx_history(self, url: 'Union[str, AccountUrl]', pagination: 'Optional[QueryPagination]' = None, scratch: 'Optional[bool]' = None, options: 'Optional[QueryOptions]' = None) -> 'MultiResponse'**: 
- **query_tx_local(self, txid: 'Union[str, bytes]', wait: 'Optional[float]' = None, ignore_pending: 'Optional[bool]' = None, options: 'Optional[QueryOptions]' = None) -> 'TransactionQueryResponse'**: 
- **query_v2(self, url: 'Union[str, AccountUrl]', options: 'Optional[QueryOptions]' = None) -> 'Union[ChainQueryResponse, TransactionQueryResponse, MultiResponse]'**: 
- **search(self, query: 'str', count: 'int' = 100, **kwargs) -> 'Dict[str, Any]'**: 
- **status(self) -> 'StatusResponse'**: 
- **submit(self, envelope: 'Dict[str, Any]', options: 'Optional[SubmitOptions]' = None) -> 'List[Dict[str, Any]]'**: 
- **validate(self, envelope: 'Dict[str, Any]', full: 'Optional[bool]' = None) -> 'List[Dict[str, Any]]'**: 
- **version(self) -> 'Dict[str, Any]'**: 

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

### PipelineClient


High-performance transaction pipeline for maximum throughput.

Features:
- Parallel transaction signing and submission
- Automatic nonce management
- Transaction status tracking and retry logic
- Priority-based processing
- Comprehensive metrics and monitoring


#### Methods

- **cleanup_completed(self, max_age: float = 3600.0)**: Clean up completed results older than max_age seconds.
- **get_result(self, submission_id: str) -> Optional[accumulate_client.performance.pipeline.SubmissionResult]**: Get result for submission ID.
- **get_stats(self) -> Dict[str, Any]**: Get pipeline statistics.
- **start(self)**: Start the pipeline workers.
- **stop(self, timeout: float = 30.0)**: Stop pipeline workers and wait for completion.
- **submit_many(self, transactions: List[accumulate_client.tx.builder.Transaction], signer: Optional[Callable] = None, priority: int = 0) -> List[str]**: 
- **submit_transaction(self, transaction: accumulate_client.tx.builder.Transaction, signer: Optional[Callable] = None, priority: int = 0, metadata: Optional[Dict[str, Any]] = None) -> str**: 
- **wait_for_all(self, submission_ids: List[str], timeout: float = 120.0) -> Dict[str, accumulate_client.performance.pipeline.SubmissionResult]**: 
- **wait_for_delivery(self, submission_id: str, timeout: float = 60.0) -> accumulate_client.performance.pipeline.SubmissionResult**: 

### PipelineConfig

Configuration for transaction pipeline.

### PipelineError

Pipeline operation error.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### PipelineTransaction

Transaction in the pipeline.

### SubmissionResult

Result of transaction submission.

### SubmissionStatus

Transaction submission status.

### Transaction


Immutable transaction representation.

Contains validated transaction data ready for submission.


#### Methods

- **get_hash(self) -> 'bytes'**: 
- **get_routing_location(self) -> 'AccountUrl'**: 
- **requires_signature(self) -> 'bool'**: 
- **to_dict(self) -> 'Dict[str, Any]'**: 

