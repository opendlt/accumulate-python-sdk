"""SmartSigner.sign_submit_and_wait must read the v3 status shape.

Found against Kermit: v3 reports ``status`` as a code NAME ("delivered", "unauthenticated", ...)
beside ``statusNo`` and an ``error`` object. Only a dict-shaped ``status`` was understood, so a
transaction was never seen as delivered or as failed and the wait fell through to "assume success",
which reported a rejected ReleaseLockedOperation as a success.
"""
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from accumulate_client.convenience import SmartSigner, TxBody

TXID = "acc://" + "ab" * 32 + "@alice.acme/tokens"


class _Key:
    def __init__(self):
        self._k = Ed25519PrivateKey.generate()

    def public_key_bytes(self):
        return self._k.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)

    def sign(self, data):
        return self._k.sign(data)


class _FakeClient:
    """Submits successfully, then answers queries from a script."""

    def __init__(self, query_results):
        self._results = list(query_results)
        self.queries = 0

    def submit(self, envelope):
        return [{"status": {"txID": TXID}}]

    def query(self, url):
        self.queries += 1
        if url == TXID:
            return self._results[min(self.queries - 2, len(self._results) - 1)]
        return {"account": {"version": 1}}  # signer-version lookup


def _wait(results, max_attempts=3):
    signer = SmartSigner(_FakeClient(results), _Key(), "acc://alice.acme/book/1")
    return signer.sign_submit_and_wait(
        principal="acc://alice.acme/tokens",
        body=TxBody.send_tokens_single("acc://bob.acme/tokens", "1"),
        max_attempts=max_attempts,
        poll_interval=0,
    )


def test_v3_delivered_string_status_is_success():
    r = _wait([{"status": "delivered", "statusNo": 201}])
    assert r.success is True and r.txid == TXID


def test_v3_rejected_transaction_is_reported_with_the_nodes_message():
    r = _wait([{
        "status": "unauthenticated",
        "statusNo": 401,
        "error": {"message": "preimage does not match hash", "code": "unauthenticated", "codeID": 401},
    }])
    assert r.success is False
    assert "preimage does not match hash" in r.error
    assert r.txid == TXID


def test_pending_then_delivered_keeps_waiting():
    r = _wait([{"status": "pending", "statusNo": 202}, {"status": "delivered", "statusNo": 201}])
    assert r.success is True


def test_never_delivered_is_a_failure_not_an_assumed_success():
    r = _wait([{"status": "pending", "statusNo": 202}], max_attempts=2)
    assert r.success is False
    assert "pending" in r.error and r.txid == TXID


def test_legacy_dict_status_still_works():
    assert _wait([{"status": {"delivered": True}}]).success is True
    bad = _wait([{"status": {"delivered": True, "error": "boom"}}])
    assert bad.success is False and "boom" in bad.error
