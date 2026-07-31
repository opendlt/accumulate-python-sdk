"""Golden bytes for `authorities` on every body type that carries it.

The authorities field number differs per transaction type. Getting it wrong --
or omitting it while the JSON body still carries it -- makes the locally
computed transaction hash disagree with the node's, and the network rejects the
transaction as *unsigned*. The symptom points nowhere near the cause, so these
bytes are pinned and shared verbatim with the Rust, Dart and C# SDKs.

Field numbers come from the protocol definition (see the generated
`CreateX.authorities` decorators in the JavaScript SDK's core types).
"""
from accumulate_client.convenience import _encode_tx_body

AUTH = ["acc://x.acme/book2"]

# field 6
CREATE_IDENTITY = (
    "0101020c6163633a2f2f782e61636d650320" + "aa" * 32
    + "04116163633a2f2f782e61636d652f626f6f6b"
    + "06126163633a2f2f782e61636d652f626f6f6b32"
)
# field 7
CREATE_TOKEN_ACCOUNT = (
    "010202106163633a2f2f782e61636d652f746f6b030a6163633a2f2f41434d45"
    "07126163633a2f2f782e61636d652f626f6f6b32"
)
# field 3
CREATE_DATA_ACCOUNT = (
    "0104020e6163633a2f2f782e61636d652f64"
    "03126163633a2f2f782e61636d652f626f6f6b32"
)
# field 9
CREATE_TOKEN = (
    "0108020e6163633a2f2f782e61636d652f7404035453540502"
    "09126163633a2f2f782e61636d652f626f6f6b32"
)
# field 5
CREATE_KEY_BOOK = (
    "010d020f6163633a2f2f782e61636d652f62320320" + "bb" * 32
    + "05126163633a2f2f782e61636d652f626f6f6b32"
)


def test_create_identity_authorities_field_6():
    body = {"type": "createIdentity", "url": "acc://x.acme", "keyHash": "aa" * 32,
            "keyBookUrl": "acc://x.acme/book", "authorities": AUTH}
    assert _encode_tx_body(body).hex() == CREATE_IDENTITY


def test_create_token_account_authorities_field_7():
    body = {"type": "createTokenAccount", "url": "acc://x.acme/tok",
            "tokenUrl": "acc://ACME", "authorities": AUTH}
    assert _encode_tx_body(body).hex() == CREATE_TOKEN_ACCOUNT


def test_create_data_account_authorities_field_3():
    body = {"type": "createDataAccount", "url": "acc://x.acme/d", "authorities": AUTH}
    assert _encode_tx_body(body).hex() == CREATE_DATA_ACCOUNT


def test_create_token_authorities_field_9():
    body = {"type": "createToken", "url": "acc://x.acme/t", "symbol": "TST",
            "precision": 2, "authorities": AUTH}
    assert _encode_tx_body(body).hex() == CREATE_TOKEN


def test_create_key_book_authorities_field_5():
    body = {"type": "createKeyBook", "url": "acc://x.acme/b2",
            "publicKeyHash": "bb" * 32, "authorities": AUTH}
    assert _encode_tx_body(body).hex() == CREATE_KEY_BOOK


def test_authorities_omitted_when_absent():
    # A body without authorities must be byte-identical to before the field
    # existed, or every previously signed transaction shape would change.
    body = {"type": "createDataAccount", "url": "acc://x.acme/d"}
    assert _encode_tx_body(body).hex() == "0104020e6163633a2f2f782e61636d652f64"
