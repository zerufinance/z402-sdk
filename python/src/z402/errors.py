"""The exception z402 raises when it stops a payment."""
from __future__ import annotations

from typing import TYPE_CHECKING

from x402.schemas import PaymentAbortedError

if TYPE_CHECKING:
    from .guard import Decision


class Z402Blocked(PaymentAbortedError):
    """z402 stopped this payment before it was signed.

    Subclasses x402's PaymentAbortedError, so code that already handles an
    aborted payment keeps working.

    Attributes:
        kind:       dont_pay | check_unavailable
        verdict:    "FLAGGED" on DONT_PAY, None when the check could not be done.
        reason:     one plain sentence saying why.
        blocked_by: the list that matched ("sanctioned", "scams", ...), or None.
        pay_to, network: the wallet that was checked and its x402 network.
    """

    def __init__(self, decision: "Decision") -> None:
        r = decision.result
        self.decision = decision
        self.kind = decision.kind
        self.verdict = r.verdict if r else None
        self.blocked_by = r.blocked_by if r else None
        self.pay_to = decision.pay_to
        self.network = decision.network
        label = "DON'T PAY" if decision.kind == "dont_pay" else decision.kind.replace("_", " ").upper()
        msg = (f"z402 stopped the payment to {decision.pay_to} on {decision.network}: "
               f"{label}: {decision.detail}")
        super().__init__(decision.detail)
        self.reason = decision.detail
        self.args = (msg,)

    def __str__(self) -> str:
        return self.args[0]


def find_block(exc: BaseException | None) -> Z402Blocked | None:
    """Return the Z402Blocked inside ``exc``, if any.

    The x402 httpx/requests wrappers re-raise hook errors as their own
    ``PaymentError(...) from e``; this walks ``__cause__`` / ``__context__``.
    """
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, Z402Blocked):
            return exc
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return None
