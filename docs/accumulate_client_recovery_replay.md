# accumulate_client.recovery.replay


Transaction replay mechanism for reliable transaction delivery.

Provides automatic transaction replay with deduplication, ordering,
and recovery strategies for ensuring transaction completion.


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


### create_fast_replay_system(client: accumulate_client.api_client.AccumulateClient) -> accumulate_client.recovery.replay.TransactionReplay

Create replay system optimized for speed.

### create_reliable_replay_system(client: accumulate_client.api_client.AccumulateClient, persistence_file: Optional[str] = None) -> accumulate_client.recovery.replay.TransactionReplay

Create replay system optimized for reliability.

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

### ABC

Helper class that provides a standard way to create an ABC using
inheritance.


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


### FileReplayStore

File-based implementation of replay store.

#### Methods

- **cleanup_old_entries(self, max_age: float) -> int**: Remove entries older than max_age seconds.
- **load_entries(self) -> List[accumulate_client.recovery.replay.ReplayEntry]**: Load all replay entries.
- **remove_entry(self, entry_id: str) -> None**: Remove replay entry.
- **save_entry(self, entry: accumulate_client.recovery.replay.ReplayEntry) -> None**: Save replay entry.
- **update_entry(self, entry: accumulate_client.recovery.replay.ReplayEntry) -> None**: Update existing replay entry.

### InMemoryReplayStore

In-memory implementation of replay store.

#### Methods

- **cleanup_old_entries(self, max_age: float) -> int**: Remove entries older than max_age seconds.
- **load_entries(self) -> List[accumulate_client.recovery.replay.ReplayEntry]**: Load all replay entries.
- **remove_entry(self, entry_id: str) -> None**: Remove replay entry.
- **save_entry(self, entry: accumulate_client.recovery.replay.ReplayEntry) -> None**: Save replay entry.
- **update_entry(self, entry: accumulate_client.recovery.replay.ReplayEntry) -> None**: Update existing replay entry.

### ReplayConfig

Configuration for transaction replay.

### ReplayEntry

Entry in transaction replay system.

### ReplayError

Transaction replay error.

#### Methods

- **add_note(self, object, /)**: Exception.add_note(note) --
- **with_traceback(self, object, /)**: Exception.with_traceback(tb) --

### ReplayStatus

Transaction replay status.

### ReplayStore


Abstract base class for replay persistence.

Defines interface for storing and retrieving replay entries
across application restarts.


#### Methods

- **cleanup_old_entries(self, max_age: float) -> int**: Remove entries older than max_age seconds.
- **load_entries(self) -> List[accumulate_client.recovery.replay.ReplayEntry]**: Load all replay entries.
- **remove_entry(self, entry_id: str) -> None**: Remove replay entry.
- **save_entry(self, entry: accumulate_client.recovery.replay.ReplayEntry) -> None**: Save replay entry.
- **update_entry(self, entry: accumulate_client.recovery.replay.ReplayEntry) -> None**: Update existing replay entry.

### Transaction


Immutable transaction representation.

Contains validated transaction data ready for submission.


#### Methods

- **get_hash(self) -> 'bytes'**: 
- **get_routing_location(self) -> 'AccountUrl'**: 
- **requires_signature(self) -> 'bool'**: 
- **to_dict(self) -> 'Dict[str, Any]'**: 

### TransactionReplay


Transaction replay system for reliable delivery.

Provides automatic replay of failed transactions with deduplication,
ordering, and configurable retry strategies.

Features:
- Automatic retry with exponential backoff
- Transaction deduplication
- Ordered replay for dependent transactions
- Persistent storage of replay queue
- Batch processing for efficiency
- Comprehensive monitoring and metrics


#### Methods

- **cancel_replay(self, entry_id: str) -> bool**: 
- **get_stats(self) -> Dict[str, Any]**: Get replay system statistics.
- **get_status(self, entry_id: str) -> Optional[accumulate_client.recovery.replay.ReplayEntry]**: Get status of replay entry.
- **start(self)**: Start the replay system.
- **stop(self, timeout: float = 30.0)**: Stop the replay system.
- **submit_transaction(self, transaction: accumulate_client.tx.builder.Transaction, metadata: Optional[Dict[str, Any]] = None) -> str**: 

