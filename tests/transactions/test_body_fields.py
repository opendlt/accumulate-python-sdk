"""
Tests for transaction body fields (Phase 2).

Tests that all transaction bodies have correct fields,
proper JSON serialization, and field validation.
"""

import pytest
from pydantic import ValidationError


# =============================================================================
# Supporting Types Tests
# =============================================================================

class TestDataEntry:
    """Tests for DataEntry types."""

    def test_accumulate_data_entry(self):
        """Test AccumulateDataEntry creation."""
        from accumulate_client.transactions import AccumulateDataEntry

        entry = AccumulateDataEntry(data=[b"hello", b"world"])

        assert entry.type == "dataEntry"
        assert len(entry.data) == 2

    def test_double_hash_data_entry(self):
        """Test DoubleHashDataEntry creation."""
        from accumulate_client.transactions import DoubleHashDataEntry

        entry = DoubleHashDataEntry(data=[b"hash1", b"hash2"])

        assert entry.type == "doubleHashDataEntry"
        assert len(entry.data) == 2


class TestTokenRecipient:
    """Tests for TokenRecipient."""

    def test_basic_creation(self):
        """Test basic token recipient."""
        from accumulate_client.transactions import TokenRecipient

        recipient = TokenRecipient(url="acc://recipient.acme", amount=1000)

        assert recipient.url == "acc://recipient.acme"
        assert recipient.amount == 1000

    def test_serialization(self):
        """Test JSON serialization."""
        from accumulate_client.transactions import TokenRecipient

        recipient = TokenRecipient(url="acc://test.acme", amount=5000)
        data = recipient.model_dump()

        assert data["url"] == "acc://test.acme"
        assert data["amount"] == 5000


class TestCreditRecipient:
    """Tests for CreditRecipient."""

    def test_basic_creation(self):
        """Test basic credit recipient."""
        from accumulate_client.transactions import CreditRecipient

        recipient = CreditRecipient(url="acc://recipient.acme/page", amount=100)

        assert recipient.url == "acc://recipient.acme/page"
        assert recipient.amount == 100


class TestKeySpecParams:
    """Tests for KeySpecParams."""

    def test_with_key_hash(self):
        """Test key spec with hash."""
        from accumulate_client.transactions import KeySpecParams

        spec = KeySpecParams(key_hash=bytes(32))

        assert spec.key_hash == bytes(32)
        assert spec.delegate is None

    def test_with_delegate(self):
        """Test key spec with delegate."""
        from accumulate_client.transactions import KeySpecParams

        spec = KeySpecParams(delegate="acc://delegate.acme/book")

        assert spec.delegate == "acc://delegate.acme/book"

    def test_alias(self):
        """Test keyHash alias."""
        from accumulate_client.transactions import KeySpecParams

        spec = KeySpecParams(keyHash=bytes(32))

        assert spec.key_hash == bytes(32)


# =============================================================================
# Key Page Operation Tests
# =============================================================================

class TestKeyPageOperations:
    """Tests for key page operation types."""

    def test_add_key_operation(self):
        """Test AddKeyOperation."""
        from accumulate_client.transactions import AddKeyOperation, KeySpecParams

        op = AddKeyOperation(entry=KeySpecParams(key_hash=bytes(32)))

        assert op.type == "add"
        assert op.entry.key_hash == bytes(32)

    def test_remove_key_operation(self):
        """Test RemoveKeyOperation."""
        from accumulate_client.transactions import RemoveKeyOperation, KeySpecParams

        op = RemoveKeyOperation(entry=KeySpecParams(key_hash=bytes(32)))

        assert op.type == "remove"

    def test_update_key_operation(self):
        """Test UpdateKeyOperation."""
        from accumulate_client.transactions import UpdateKeyOperation, KeySpecParams

        old_entry = KeySpecParams(key_hash=bytes(32))
        new_entry = KeySpecParams(key_hash=bytes.fromhex("ab" * 32))

        op = UpdateKeyOperation(old_entry=old_entry, new_entry=new_entry)

        assert op.type == "update"
        assert op.old_entry.key_hash == bytes(32)
        assert op.new_entry.key_hash == bytes.fromhex("ab" * 32)

    def test_set_threshold_operation(self):
        """Test SetThresholdKeyPageOperation."""
        from accumulate_client.transactions import SetThresholdKeyPageOperation

        op = SetThresholdKeyPageOperation(threshold=2)

        assert op.type == "setThreshold"
        assert op.threshold == 2

    def test_set_reject_threshold_operation(self):
        """Test SetRejectThresholdKeyPageOperation."""
        from accumulate_client.transactions import SetRejectThresholdKeyPageOperation

        op = SetRejectThresholdKeyPageOperation(threshold=1)

        assert op.type == "setRejectThreshold"
        assert op.threshold == 1

    def test_set_response_threshold_operation(self):
        """Test SetResponseThresholdKeyPageOperation."""
        from accumulate_client.transactions import SetResponseThresholdKeyPageOperation

        op = SetResponseThresholdKeyPageOperation(threshold=3)

        assert op.type == "setResponseThreshold"
        assert op.threshold == 3

    def test_update_allowed_operation(self):
        """Test UpdateAllowedKeyPageOperation."""
        from accumulate_client.transactions import UpdateAllowedKeyPageOperation

        op = UpdateAllowedKeyPageOperation(allow=[1, 2, 3], deny=[4, 5])

        assert op.type == "updateAllowed"
        assert op.allow == [1, 2, 3]
        assert op.deny == [4, 5]


# =============================================================================
# Account Auth Operation Tests
# =============================================================================

class TestAccountAuthOperations:
    """Tests for account auth operation types."""

    def test_add_authority_operation(self):
        """Test AddAccountAuthorityOperation."""
        from accumulate_client.transactions import AddAccountAuthorityOperation

        op = AddAccountAuthorityOperation(authority="acc://new-auth.acme/book")

        assert op.type == "addAuthority"
        assert op.authority == "acc://new-auth.acme/book"

    def test_remove_authority_operation(self):
        """Test RemoveAccountAuthorityOperation."""
        from accumulate_client.transactions import RemoveAccountAuthorityOperation

        op = RemoveAccountAuthorityOperation(authority="acc://old-auth.acme/book")

        assert op.type == "removeAuthority"
        assert op.authority == "acc://old-auth.acme/book"

    def test_enable_authority_operation(self):
        """Test EnableAccountAuthOperation."""
        from accumulate_client.transactions import EnableAccountAuthOperation

        op = EnableAccountAuthOperation(authority="acc://test.acme/book")

        assert op.type == "enable"
        assert op.authority == "acc://test.acme/book"

    def test_disable_authority_operation(self):
        """Test DisableAccountAuthOperation."""
        from accumulate_client.transactions import DisableAccountAuthOperation

        op = DisableAccountAuthOperation(authority="acc://test.acme/book")

        assert op.type == "disable"


# =============================================================================
# User Transaction Body Tests
# =============================================================================

class TestCreateIdentityBody:
    """Tests for CreateIdentity transaction body."""

    def test_basic_creation(self):
        """Test basic identity creation body."""
        from accumulate_client.transactions import CreateIdentityBody

        body = CreateIdentityBody(url="acc://new-identity.acme")

        assert body.type == "createIdentity"
        assert body.url == "acc://new-identity.acme"

    def test_with_key_hash(self):
        """Test with key hash."""
        from accumulate_client.transactions import CreateIdentityBody

        body = CreateIdentityBody(
            url="acc://new-identity.acme",
            key_hash=bytes(32)
        )

        assert body.key_hash == bytes(32)

    def test_with_key_book_url(self):
        """Test with key book URL."""
        from accumulate_client.transactions import CreateIdentityBody

        body = CreateIdentityBody(
            url="acc://new-identity.acme",
            key_book_url="acc://existing.acme/book"
        )

        assert body.key_book_url == "acc://existing.acme/book"

    def test_with_authorities(self):
        """Test with authorities list."""
        from accumulate_client.transactions import CreateIdentityBody

        body = CreateIdentityBody(
            url="acc://new-identity.acme",
            authorities=["acc://auth1.acme/book", "acc://auth2.acme/book"]
        )

        assert len(body.authorities) == 2

    def test_serialization(self):
        """Test JSON serialization."""
        from accumulate_client.transactions import CreateIdentityBody

        body = CreateIdentityBody(
            url="acc://test.acme",
            keyHash=bytes(32),
            keyBookUrl="acc://test.acme/book"
        )

        data = body.model_dump(by_alias=True)

        assert data["type"] == "createIdentity"
        assert "keyHash" in data
        assert "keyBookUrl" in data


class TestCreateTokenAccountBody:
    """Tests for CreateTokenAccount transaction body."""

    def test_basic_creation(self):
        """Test basic token account creation."""
        from accumulate_client.transactions import CreateTokenAccountBody

        body = CreateTokenAccountBody(
            url="acc://test.acme/tokens",
            token_url="acc://ACME"
        )

        assert body.type == "createTokenAccount"
        assert body.url == "acc://test.acme/tokens"
        assert body.token_url == "acc://ACME"

    def test_with_authorities(self):
        """Test with authorities."""
        from accumulate_client.transactions import CreateTokenAccountBody

        body = CreateTokenAccountBody(
            url="acc://test.acme/tokens",
            token_url="acc://ACME",
            authorities=["acc://test.acme/book"]
        )

        assert body.authorities == ["acc://test.acme/book"]


class TestSendTokensBody:
    """Tests for SendTokens transaction body."""

    def test_basic_send(self):
        """Test basic token send."""
        from accumulate_client.transactions import SendTokensBody, TokenRecipient

        body = SendTokensBody(
            to=[TokenRecipient(url="acc://recipient.acme", amount=1000)]
        )

        assert body.type == "sendTokens"
        assert len(body.to) == 1
        assert body.to[0].amount == 1000

    def test_multiple_recipients(self):
        """Test multiple recipients."""
        from accumulate_client.transactions import SendTokensBody, TokenRecipient

        body = SendTokensBody(
            to=[
                TokenRecipient(url="acc://r1.acme", amount=100),
                TokenRecipient(url="acc://r2.acme", amount=200),
                TokenRecipient(url="acc://r3.acme", amount=300),
            ]
        )

        assert len(body.to) == 3
        total = sum(r.amount for r in body.to)
        assert total == 600

    def test_with_hash(self):
        """Test with hash field."""
        from accumulate_client.transactions import SendTokensBody, TokenRecipient

        body = SendTokensBody(
            to=[TokenRecipient(url="acc://test.acme", amount=100)],
            hash=bytes(32)
        )

        assert body.hash == bytes(32)


class TestWriteDataBody:
    """Tests for WriteData transaction body."""

    def test_basic_write(self):
        """Test basic data write."""
        from accumulate_client.transactions import WriteDataBody, AccumulateDataEntry

        entry = AccumulateDataEntry(data=[b"hello world"])
        body = WriteDataBody(entry=entry)

        assert body.type == "writeData"
        assert body.entry.data == [b"hello world"]

    def test_scratch_option(self):
        """Test scratch option."""
        from accumulate_client.transactions import WriteDataBody, AccumulateDataEntry

        entry = AccumulateDataEntry(data=[b"temp data"])
        body = WriteDataBody(entry=entry, scratch=True)

        assert body.scratch is True

    def test_write_to_state_option(self):
        """Test writeToState option."""
        from accumulate_client.transactions import WriteDataBody, AccumulateDataEntry

        entry = AccumulateDataEntry(data=[b"state data"])
        body = WriteDataBody(entry=entry, write_to_state=True)

        assert body.write_to_state is True


class TestWriteDataToBody:
    """Tests for WriteDataTo transaction body."""

    def test_basic_write_to(self):
        """Test basic write to recipient."""
        from accumulate_client.transactions import WriteDataToBody, AccumulateDataEntry

        entry = AccumulateDataEntry(data=[b"data"])
        body = WriteDataToBody(recipient="acc://recipient.acme/data", entry=entry)

        assert body.type == "writeDataTo"
        assert body.recipient == "acc://recipient.acme/data"


class TestAcmeFaucetBody:
    """Tests for AcmeFaucet transaction body."""

    def test_basic_faucet(self):
        """Test basic faucet request."""
        from accumulate_client.transactions import AcmeFaucetBody

        body = AcmeFaucetBody(url="acc://test.acme")

        assert body.type == "acmeFaucet"
        assert body.url == "acc://test.acme"


class TestCreateTokenBody:
    """Tests for CreateToken transaction body."""

    def test_basic_token(self):
        """Test basic token creation."""
        from accumulate_client.transactions import CreateTokenBody

        body = CreateTokenBody(
            url="acc://test.acme/mytoken",
            symbol="MTK",
            precision=8
        )

        assert body.type == "createToken"
        assert body.url == "acc://test.acme/mytoken"
        assert body.symbol == "MTK"
        assert body.precision == 8

    def test_with_supply_limit(self):
        """Test with supply limit."""
        from accumulate_client.transactions import CreateTokenBody

        body = CreateTokenBody(
            url="acc://test.acme/token",
            symbol="LTD",
            precision=8,
            supply_limit=21000000
        )

        assert body.supply_limit == 21000000


class TestIssueTokensBody:
    """Tests for IssueTokens transaction body."""

    def test_issue_to_single(self):
        """Test issuing to single recipient."""
        from accumulate_client.transactions import IssueTokensBody

        body = IssueTokensBody(
            recipient="acc://recipient.acme/tokens",
            amount=1000000
        )

        assert body.type == "issueTokens"
        assert body.amount == 1000000

    def test_issue_to_multiple(self):
        """Test issuing to multiple recipients."""
        from accumulate_client.transactions import IssueTokensBody, TokenRecipient

        body = IssueTokensBody(
            to=[
                TokenRecipient(url="acc://r1.acme", amount=100),
                TokenRecipient(url="acc://r2.acme", amount=200),
            ]
        )

        assert len(body.to) == 2


class TestBurnTokensBody:
    """Tests for BurnTokens transaction body."""

    def test_basic_burn(self):
        """Test basic token burn."""
        from accumulate_client.transactions import BurnTokensBody

        body = BurnTokensBody(amount=500000)

        assert body.type == "burnTokens"
        assert body.amount == 500000


class TestCreateKeyPageBody:
    """Tests for CreateKeyPage transaction body."""

    def test_basic_key_page(self):
        """Test basic key page creation."""
        from accumulate_client.transactions import CreateKeyPageBody, KeySpecParams

        body = CreateKeyPageBody(
            keys=[KeySpecParams(key_hash=bytes(32))]
        )

        assert body.type == "createKeyPage"
        assert len(body.keys) == 1

    def test_multiple_keys(self):
        """Test with multiple keys."""
        from accumulate_client.transactions import CreateKeyPageBody, KeySpecParams

        body = CreateKeyPageBody(
            keys=[
                KeySpecParams(key_hash=bytes(32)),
                KeySpecParams(delegate="acc://delegate.acme/book"),
            ]
        )

        assert len(body.keys) == 2


class TestCreateKeyBookBody:
    """Tests for CreateKeyBook transaction body."""

    def test_basic_key_book(self):
        """Test basic key book creation."""
        from accumulate_client.transactions import CreateKeyBookBody

        body = CreateKeyBookBody(
            url="acc://test.acme/book",
            public_key_hash=bytes(32)
        )

        assert body.type == "createKeyBook"
        assert body.url == "acc://test.acme/book"
        assert body.public_key_hash == bytes(32)


class TestAddCreditsBody:
    """Tests for AddCredits transaction body."""

    def test_basic_add_credits(self):
        """Test basic credit addition."""
        from accumulate_client.transactions import AddCreditsBody

        body = AddCreditsBody(
            recipient="acc://test.acme/page",
            amount=100000000
        )

        assert body.type == "addCredits"
        assert body.recipient == "acc://test.acme/page"
        assert body.amount == 100000000

    def test_with_oracle(self):
        """Test with oracle price."""
        from accumulate_client.transactions import AddCreditsBody

        body = AddCreditsBody(
            recipient="acc://test.acme/page",
            amount=100000000,
            oracle=500
        )

        assert body.oracle == 500


class TestBurnCreditsBody:
    """Tests for BurnCredits transaction body."""

    def test_basic_burn_credits(self):
        """Test basic credit burn."""
        from accumulate_client.transactions import BurnCreditsBody

        body = BurnCreditsBody(amount=1000)

        assert body.type == "burnCredits"
        assert body.amount == 1000


class TestTransferCreditsBody:
    """Tests for TransferCredits transaction body."""

    def test_basic_transfer(self):
        """Test basic credit transfer."""
        from accumulate_client.transactions import TransferCreditsBody, CreditRecipient

        body = TransferCreditsBody(
            to=[CreditRecipient(url="acc://recipient.acme/page", amount=500)]
        )

        assert body.type == "transferCredits"
        assert len(body.to) == 1


class TestUpdateKeyPageBody:
    """Tests for UpdateKeyPage transaction body."""

    def test_basic_update(self):
        """Test basic key page update."""
        from accumulate_client.transactions import (
            UpdateKeyPageBody,
            AddKeyOperation,
            KeySpecParams
        )

        body = UpdateKeyPageBody(
            operation=[AddKeyOperation(entry=KeySpecParams(key_hash=bytes(32)))]
        )

        assert body.type == "updateKeyPage"
        assert len(body.operation) == 1


class TestLockAccountBody:
    """Tests for LockAccount transaction body."""

    def test_basic_lock(self):
        """Test basic account lock."""
        from accumulate_client.transactions import LockAccountBody

        body = LockAccountBody(height=1000)

        assert body.type == "lockAccount"
        assert body.height == 1000


class TestUpdateAccountAuthBody:
    """Tests for UpdateAccountAuth transaction body."""

    def test_basic_update(self):
        """Test basic auth update."""
        from accumulate_client.transactions import (
            UpdateAccountAuthBody,
            AddAccountAuthorityOperation
        )

        body = UpdateAccountAuthBody(
            operations=[AddAccountAuthorityOperation(authority="acc://new.acme/book")]
        )

        assert body.type == "updateAccountAuth"
        assert len(body.operations) == 1


class TestUpdateKeyBody:
    """Tests for UpdateKey transaction body."""

    def test_basic_key_update(self):
        """Test basic key update."""
        from accumulate_client.transactions import UpdateKeyBody

        body = UpdateKeyBody(new_key_hash=bytes(32))

        assert body.type == "updateKey"
        assert body.new_key_hash == bytes(32)


# =============================================================================
# Synthetic Transaction Body Tests
# =============================================================================

class TestSyntheticBodies:
    """Tests for synthetic transaction bodies."""

    def test_synthetic_create_identity(self):
        """Test SyntheticCreateIdentityBody."""
        from accumulate_client.transactions import SyntheticCreateIdentityBody

        body = SyntheticCreateIdentityBody(
            cause="acc://test@abc123",
            initiator="acc://initiator.acme",
            fee_refund=1000,
            index=0,
            accounts=[]
        )

        assert body.type == "syntheticCreateIdentity"
        assert body.cause == "acc://test@abc123"

    def test_synthetic_deposit_tokens(self):
        """Test SyntheticDepositTokensBody."""
        from accumulate_client.transactions import SyntheticDepositTokensBody

        body = SyntheticDepositTokensBody(
            cause="acc://test@abc123",
            initiator="acc://initiator.acme",
            fee_refund=1000,
            index=0,
            token="acc://ACME",
            amount=1000000,
            is_issuer=False,
            is_refund=False
        )

        assert body.type == "syntheticDepositTokens"
        assert body.token == "acc://ACME"
        assert body.amount == 1000000

    def test_synthetic_deposit_credits(self):
        """Test SyntheticDepositCreditsBody."""
        from accumulate_client.transactions import SyntheticDepositCreditsBody

        body = SyntheticDepositCreditsBody(
            cause="acc://test@abc123",
            initiator="acc://initiator.acme",
            fee_refund=1000,
            index=0,
            amount=5000,
            is_refund=False
        )

        assert body.type == "syntheticDepositCredits"
        assert body.amount == 5000


# =============================================================================
# System Transaction Body Tests
# =============================================================================

class TestSystemBodies:
    """Tests for system transaction bodies."""

    def test_system_genesis(self):
        """Test SystemGenesisBody."""
        from accumulate_client.transactions import SystemGenesisBody

        body = SystemGenesisBody()

        assert body.type == "systemGenesis"

    def test_system_write_data(self):
        """Test SystemWriteDataBody."""
        from accumulate_client.transactions import SystemWriteDataBody, AccumulateDataEntry

        entry = AccumulateDataEntry(data=[b"system data"])
        body = SystemWriteDataBody(entry=entry)

        assert body.type == "systemWriteData"


# =============================================================================
# Serialization Tests
# =============================================================================

class TestSerialization:
    """Tests for transaction body serialization."""

    def test_alias_serialization(self):
        """Test that aliases are used in serialization."""
        from accumulate_client.transactions import CreateIdentityBody

        body = CreateIdentityBody(
            url="acc://test.acme",
            key_hash=bytes(32),
            key_book_url="acc://test.acme/book"
        )

        data = body.model_dump(by_alias=True, exclude_none=True)

        assert "keyHash" in data
        assert "keyBookUrl" in data
        assert "key_hash" not in data

    def test_exclude_none(self):
        """Test excluding None values."""
        from accumulate_client.transactions import CreateIdentityBody

        body = CreateIdentityBody(url="acc://test.acme")

        data = body.model_dump(by_alias=True, exclude_none=True)

        assert "keyHash" not in data
        assert "keyBookUrl" not in data
        assert "authorities" not in data
