# accumulate_client.client.streaming


Streaming Accumulate client for real-time data.

Provides high-level streaming interface wrapping WebSocket transport
with helper methods for common streaming patterns.


## Functions

### collect_events(stream: AsyncIterator[accumulate_client.transport.ws.Event], count: int, timeout: Optional[float] = None) -> list[accumulate_client.transport.ws.Event]


Collect a specific number of events from a stream.

Args:
    stream: Event stream
    count: Number of events to collect
    timeout: Optional timeout in seconds

Returns:
    List of collected events

Raises:
    asyncio.TimeoutError: If timeout is reached


### stream_until_condition(stream: AsyncIterator[accumulate_client.transport.ws.Event], condition: Callable[[accumulate_client.transport.ws.Event], bool], timeout: Optional[float] = None) -> accumulate_client.transport.ws.Event


Stream events until a condition is met.

Args:
    stream: Event stream
    condition: Function that returns True when condition is met
    timeout: Optional timeout in seconds

Returns:
    Event that satisfied the condition

Raises:
    asyncio.TimeoutError: If timeout is reached


### ws_url_from_http(http_url: str, ws_path: str = '/v3/ws') -> str


Convert HTTP URL to WebSocket URL.

Args:
    http_url: HTTP endpoint URL
    ws_path: WebSocket path to append

Returns:
    WebSocket URL


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

### AnchorEvent

Anchor-related event.

### Any

Special type indicating an unconstrained type.

- Any is compatible with every type.
- Any assumed to have all methods.
- All values assumed to be instances of Any.

Note that all the above statements are true from the point of view of
static type checkers. At runtime, Any should not be used with instance
checks.


### BlockEvent

Block-related event.

### Event

Base event type for WebSocket messages.

### LogEvent

Log event.

### StreamingAccumulateClient


Streaming Accumulate client with WebSocket support.

Provides high-level streaming interface for real-time Accumulate data:
- Block streaming
- Transaction status tracking
- Directory anchor monitoring
- Log streaming
- Snapshot-then-stream patterns


#### Methods

- **add_metrics_hook(self, hook: Callable[[accumulate_client.transport.ws.Event], NoneType]) -> None**: 
- **connect(self) -> None**: Connect to WebSocket server.
- **disconnect(self) -> None**: Disconnect from WebSocket server.
- **snapshot_then_stream(self, query_fn: Callable[[], Any], stream_fn: Callable[[], AsyncIterator[accumulate_client.transport.ws.Event]], snapshot_key: str = 'height') -> AsyncIterator[accumulate_client.transport.ws.Event]**: 
- **stream_blocks(self, start_height: Optional[int] = None, filter_params: Optional[Dict[str, Any]] = None) -> AsyncIterator[accumulate_client.transport.ws.BlockEvent]**: 
- **stream_directory_anchors(self, directory: Optional[str] = None, filter_params: Optional[Dict[str, Any]] = None) -> AsyncIterator[accumulate_client.transport.ws.AnchorEvent]**: 
- **stream_logs(self, level: Optional[str] = None, source: Optional[str] = None, filter_params: Optional[Dict[str, Any]] = None) -> AsyncIterator[accumulate_client.transport.ws.LogEvent]**: 
- **stream_tx_status(self, url_or_id: Union[str, list], follow_children: bool = False) -> AsyncIterator[accumulate_client.transport.ws.TxStatusEvent]**: 
- **track_multiple_txs(self, tx_ids: list, timeout: float = 60.0) -> Dict[str, accumulate_client.transport.ws.TxStatusEvent]**: 
- **wait_for_tx_completion(self, tx_id: str, timeout: float = 60.0, states: Optional[list] = None) -> accumulate_client.transport.ws.TxStatusEvent**: 

### TxStatusEvent

Transaction status event.

### WebSocketClient


Async WebSocket client with automatic reconnection and event streaming.

Features:
- Automatic reconnection with exponential backoff and jitter
- Ping/pong handling for connection health
- Backpressure management with configurable queue behavior
- Event subscription and routing
- Graceful error handling and recovery


#### Methods

- **add_event_hook(self, hook: <built-in function callable>) -> None**: Add an event hook for metrics/logging.
- **connect(self) -> None**: Connect to WebSocket server.
- **disconnect(self) -> None**: Disconnect from WebSocket server.
- **send(self, method: str, params: Optional[Dict[str, Any]] = None) -> None**: 
- **subscribe(self, stream: str, params: Optional[Dict[str, Any]] = None) -> AsyncIterator[accumulate_client.transport.ws.Event]**: 

### WebSocketConfig

Configuration for WebSocket client.

