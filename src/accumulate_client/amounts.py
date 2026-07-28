"""ACME amount helpers.

Accumulate denominates ACME in *base units* where **1 ACME = 1e8 base units**.
Passing whole ACME where base units are expected (or vice-versa) is the single
most common integration bug. Use :class:`Amount` to convert explicitly:

    from accumulate_client import Amount, TxBody

    body = TxBody.send_tokens("acc://bob.acme/tokens", Amount.acme(5))   # 5 ACME
    body = TxBody.send_tokens("acc://bob.acme/tokens", Amount.base_units("500000000"))

``Amount`` stringifies to its base-unit value, so it is a drop-in for the
string/int amount arguments the ``TxBody`` builders already accept.
"""

from __future__ import annotations

from decimal import Decimal

ACME_PRECISION = 8
ACME_BASE_UNITS = 10 ** ACME_PRECISION  # 100_000_000 base units == 1 ACME

__all__ = ["Amount", "ACME_PRECISION", "ACME_BASE_UNITS"]


class Amount:
    """An ACME token amount, stored internally as integer base units."""

    __slots__ = ("_base_units",)

    def __init__(self, base_units: int) -> None:
        self._base_units = int(base_units)

    @classmethod
    def acme(cls, whole_acme: "int | float | str | Decimal") -> "Amount":
        """Create from whole ACME. ``Amount.acme(1)`` == 1e8 base units.

        Accepts int/float/str/Decimal; the value is scaled by 1e8 and truncated
        to an integer number of base units.
        """
        scaled = Decimal(str(whole_acme)) * ACME_BASE_UNITS
        return cls(int(scaled.to_integral_value(rounding="ROUND_DOWN")))

    @classmethod
    def base_units(cls, units: "int | str") -> "Amount":
        """Create from raw base units (what the wire format uses)."""
        return cls(int(units))

    @classmethod
    def token(cls, whole_tokens: "int | float | str | Decimal", precision: int) -> "Amount":
        """Create from whole units of a **custom token** with the given precision.

        Custom tokens declare their own precision when created; the wire format
        is always base units. ``Amount.token(1000, 8)`` is 1000 whole tokens =
        ``100000000000`` base units.

        Without this helper the only options are hand-computing a power of ten
        or passing a raw base-unit string, and both are routinely got wrong:
        issuing ``1000`` against a precision-8 token mints ``0.00001`` tokens,
        not 1000. The transaction succeeds either way, so the mistake is silent.

        >>> Amount.token(1000, 8).to_wire()
        '100000000000'
        >>> Amount.token(100, 2).to_wire()
        '10000'
        >>> Amount.token(1000, 0).to_wire()
        '1000'
        """
        scaled = Decimal(str(whole_tokens)) * (10 ** int(precision))
        return cls(int(scaled.to_integral_value(rounding="ROUND_DOWN")))

    @classmethod
    def credits(cls, credit_count: int, oracle_price: int) -> "Amount":
        """ACME base units needed to buy ``credit_count`` credits at ``oracle_price``.

        ``oracle_price`` is the integer ACME/credits oracle value from the network
        oracle query. Returned amount is the ACME (in base units) to spend.
        """
        # credits are quoted in hundredths; base = credits * 1e8 * 100 / oracle
        base = (int(credit_count) * ACME_BASE_UNITS * 100) // int(oracle_price)
        return cls(base)

    @property
    def as_base_units(self) -> int:
        """The amount as an integer number of base units."""
        return self._base_units

    def to_wire(self) -> str:
        """Wire representation: base units as a string (what ``TxBody`` expects)."""
        return str(self._base_units)

    def to_acme(self) -> Decimal:
        """The amount expressed in whole ACME."""
        return Decimal(self._base_units) / ACME_BASE_UNITS

    def to_token(self, precision: int) -> Decimal:
        """The amount in whole units of a token with the given precision.

        >>> Amount.base_units(100000000000).to_token(8)
        Decimal('1000')
        """
        return Decimal(self._base_units) / (10 ** int(precision))

    def __str__(self) -> str:  # so it drops into str/int amount args transparently
        return self.to_wire()

    def __int__(self) -> int:
        return self._base_units

    def __repr__(self) -> str:
        return f"Amount({self._base_units} base units = {self.to_acme()} ACME)"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Amount) and other._base_units == self._base_units

    def __hash__(self) -> int:
        return hash(self._base_units)
