# Accumulate Python SDK - Advanced Features Documentation

This documentation covers the advanced features introduced in Phase 3.

## Core Client Features

- **[Streaming Client](accumulate_client_client_streaming.md)** - Real-time WebSocket streaming

## Transport Layer

- **[WebSocket Transport](accumulate_client_transport_ws.md)** - WebSocket connection management

## Performance Optimization

- **[HTTP Connection Pool](accumulate_client_performance_pool.md)** - HTTP Connection Pool implementation
- **[Request Batching](accumulate_client_performance_batch.md)** - Request Batching implementation
- **[Transaction Pipeline](accumulate_client_performance_pipeline.md)** - Transaction Pipeline implementation

## Error Recovery

- **[Retry Policies](accumulate_client_recovery_retry.md)** - Retry Policies implementation
- **[Circuit Breaker](accumulate_client_recovery_circuit_breaker.md)** - Circuit Breaker implementation
- **[Transaction Replay](accumulate_client_recovery_replay.md)** - Transaction Replay implementation

## Monitoring & Telemetry

- **[Metrics Registry](accumulate_client_monitoring_metrics.md)** - Metrics Registry implementation
- **[Metrics Exporters](accumulate_client_monitoring_exporters.md)** - Metrics Exporters implementation
- **[Instrumentation](accumulate_client_monitoring_instrumentation.md)** - Instrumentation implementation

## Quick Start Examples


### WebSocket Streaming

```python
from accumulate_client import StreamingAccumulateClient, AccumulateClient

async with StreamingAccumulateClient(AccumulateClient("https://api.accumulate.io/v3")) as streaming:
    async for block in streaming.stream_blocks():
        print(f"Block {block.block_height}")
```

### Request Batching

```python
from accumulate_client.performance import BatchClient

async with BatchClient("https://api.accumulate.io/v3") as batch:
    results = await batch.submit_many([
        {"method": "query", "params": {"url": "acc://account1"}},
        {"method": "query", "params": {"url": "acc://account2"}}
    ])
```

### Error Recovery

```python
from accumulate_client.recovery import ExponentialBackoff

retry_policy = ExponentialBackoff(max_attempts=5)
result = await retry_policy.execute(client.submit, transaction)
```

### Metrics Export

```python
from accumulate_client.monitoring import get_registry, JsonExporter

registry = get_registry()
exporter = JsonExporter()
metrics_json = exporter.export(registry)
print(metrics_json)
```
