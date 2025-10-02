# Write-Check: C:\Accumulate_Stuff\opendlt-python-v2v3-sdk\unified\tests\conftest.py
"""
Test bootstrap:
- Force-add unified/src to sys.path (collection-time safe)
- Record environment (devnet, Python) in a small JSON snapshot
- Provide a tiny helper marker for later bucketing
"""
import os
import sys
import json
import socket
import pathlib
import pytest

ABS_ROOT = pathlib.Path(r"C:\Accumulate_Stuff\opendlt-python-v2v3-sdk\unified").resolve()
SRC = ABS_ROOT / "src"
REPORTS = ABS_ROOT / "reports"

# Ensure unified/src importability at collect-time
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

def _devnet_health(timeout=0.8) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 26660), timeout=timeout):
            return True
    except Exception:
        return False

@pytest.fixture(scope="session", autouse=True)
def _env_report():
    REPORTS.mkdir(parents=True, exist_ok=True)
    snap = {
        "python": sys.version,
        "devnet_reachable": _devnet_health(),
        "cwd": str(pathlib.Path.cwd()),
        "env": {k: os.environ.get(k, "") for k in ("ACC_DEVNET_ENDPOINT","PYTHONPATH")},
    }
    p = REPORTS / "test_env_snapshot.json"
    with open(p, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2)
    yield


@pytest.fixture
def builder_registry():
    """Registry of all available transaction builders."""
    from accumulate_client.tx.builders.registry import BUILDER_REGISTRY

    # Return the actual builder classes, not instances
    return BUILDER_REGISTRY.copy()


@pytest.fixture
def fake_keypair():
    """Provide a deterministic Ed25519 key pair for testing."""
    from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

    # Use a deterministic seed for consistent test results
    seed = b'test_seed_for_deterministic_key_pair'[:32]
    private_key = Ed25519PrivateKey.from_seed(seed)
    public_key = private_key.public_key()

    return (private_key, public_key)


@pytest.fixture
def mock_client():
    """Provide a mock Accumulate client for testing API methods."""
    import sys
    import pathlib

    # Ensure tests directory is in Python path
    tests_dir = pathlib.Path(__file__).parent
    if str(tests_dir) not in sys.path:
        sys.path.insert(0, str(tests_dir))

    from helpers.mocks import EnhancedMockClient
    return EnhancedMockClient()


@pytest.fixture
def metrics_registry():
    """Provide a metrics registry for testing."""
    from accumulate_client.monitoring.metrics import MetricsRegistry
    return MetricsRegistry()