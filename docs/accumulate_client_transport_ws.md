# accumulate_client.transport.ws


WebSocket transport for Accumulate streaming APIs.

Provides async WebSocket client with reconnection, ping/pong handling,
and backpressure management for real-time event streaming.


## Constants

- **HAS_WEBSOCKETS** (bool): `True`

## Functions

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


### urlparse(url, scheme='', allow_fragments=True)

Parse a URL into 6 components:
<scheme>://<netloc>/<path>;<params>?<query>#<fragment>

The result is a named 6-tuple with fields corresponding to the
above. It is either a ParseResult or ParseResultBytes object,
depending on the type of the url parameter.

The username, password, hostname, and port sub-components of netloc
can also be accessed as attributes of the returned object.

The scheme argument provides the default value of the scheme
component when no scheme is found in url.

If allow_fragments is False, no attempt is made to separate the
fragment component from the previous component, which can be either
path or query.

Note that % escapes are not expanded.


### ws_url_from_http(http_url: str, ws_path: str = '/v3/ws') -> str


Convert HTTP URL to WebSocket URL.

Args:
    http_url: HTTP endpoint URL
    ws_path: WebSocket path to append

Returns:
    WebSocket URL


## Classes

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

### ConnectionClosed


Raised when trying to interact with a closed connection.

Attributes:
    rcvd: If a close frame was received, its code and reason are available
        in ``rcvd.code`` and ``rcvd.reason``.
    sent: If a close frame was sent, its code and reason are available
        in ``sent.code`` and ``sent.reason``.
    rcvd_then_sent: If close frames were received and sent, this attribute
        tells in which order this happened, from the perspective of this
        side of the connection.



#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### Event

Base event type for WebSocket messages.

### InvalidStatusCode


Raised when a handshake response status code is invalid.



#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### LogEvent

Log event.

### ProtocolError

WebSocket protocol violation.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### ReconnectExceeded

Maximum reconnection attempts exceeded.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

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

### WebSocketError

Base WebSocket error.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

