"""Attach z402 to an x402 client so every payment is checked before it is signed.

    z402.guard(client)                                  # block every list (default)
    z402.guard(client, block=["sanctioned", "scams"])   # only these lists

The z402 check API answers DONT_PAY or PAY for the payTo wallet. DONT_PAY raises
Z402Blocked before anything is signed. If the check cannot be done (down,
timeout, error), the payment stops too.

Hook point (x402 2.22.0): ``x402Client.on_before_payment_creation`` /
``x402ClientSync.on_before_payment_creation`` (x402/client.py:128, :316).
The core runs these hooks after it has selected one ``accepts`` entry and
before it calls the scheme signer (x402/client_base.py:742-763 for v2,
:848-869 for v1). An exception raised by the hook propagates out of
``create_payment_payload``, so no signature is ever made.

One registration covers every x402 transport that ends in
``create_payment_payload``: httpx, requests and MCP.

The hook receives ``PaymentCreationContext(payment_required,
selected_requirements)`` only. It has no access to the signer or the key.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Literal

from x402 import x402Client, x402ClientSync

from .check import (DEFAULT_BASE_URL, AsyncCheckClient, CheckClient, CheckResult,
                    CheckUnavailable, normalize_block)
from .errors import Z402Blocked

log = logging.getLogger("z402")

Action = Literal["stop", "warn"]


@dataclass(frozen=True)
class Decision:
    action: Literal["pay", "stop", "warn"]
    kind: str                         # pay | dont_pay | check_unavailable
    pay_to: str                       # the wallet that was checked
    network: str
    result: CheckResult | None
    detail: str


def decide(result: CheckResult | None, error: Exception | None, pay_to: str, network: str,
           on_unavailable: Action = "stop") -> Decision:
    """Pure decision table. ``result`` is None exactly when ``error`` is set.

    DONT_PAY always stops. ``on_unavailable`` ("stop" default, or "warn" = pay and report)
    applies only when the check could not be done.
    """
    if result is None:
        return Decision(on_unavailable, "check_unavailable", pay_to, network, None,
                        f"the z402 check could not be completed ({error})")
    if result.decision == "DONT_PAY":
        return Decision("stop", "dont_pay", pay_to, network, result, result.sentence)
    return Decision("pay", "pay", pay_to, network, result, result.sentence)


def settings(api_key: str | None, base_url: str | None, timeout: float | None,
             block: Iterable[str] | None, interacted: bool) -> dict[str, Any]:
    """Check-client arguments from the call, then Z402_API_KEY / Z402_API_URL, then defaults."""
    kw: dict[str, Any] = {
        "base_url": base_url or os.getenv("Z402_API_URL") or DEFAULT_BASE_URL,
        "api_key": api_key if api_key is not None else os.getenv("Z402_API_KEY"),
        "block": normalize_block(block),            # ValueError now, not at payment time
        "interacted": bool(interacted),
    }
    if timeout is not None:
        kw["timeout"] = timeout
    return kw


def _target(ctx: Any) -> tuple[str, str]:
    sel = ctx.selected_requirements
    return str(getattr(sel, "pay_to", "") or ""), str(getattr(sel, "network", "") or "")


def _apply(decision: Decision, on_warn: Callable[[Decision], None] | None,
           on_decision: Callable[[Decision], None] | None) -> None:
    if on_decision is not None:
        on_decision(decision)
    if decision.action == "pay":
        return
    if decision.action == "warn":
        if on_warn is not None:
            on_warn(decision)
        else:
            log.warning("z402: paying %s on %s although %s: %s", decision.pay_to,
                        decision.network, decision.kind, decision.detail)
        return
    raise Z402Blocked(decision)


def guard(
    client: x402Client | x402ClientSync,
    *,
    block: Iterable[str] | None = None,
    interacted: bool = True,
    api_key: str | None = None,
    base_url: str | None = None,
    timeout: float | None = None,
    on_unavailable: Action = "stop",
    on_warn: Callable[[Decision], None] | None = None,
    on_decision: Callable[[Decision], None] | None = None,
    check_client: CheckClient | AsyncCheckClient | None = None,
) -> x402Client | x402ClientSync:
    """Register the z402 check on ``client`` and return the same client.

    ``block``: list names to block (default None = all of ``z402.GROUPS``).
    ``interacted``: also block wallets that dealt with listed wallets (default True).
    ``api_key`` / ``base_url`` default to ``Z402_API_KEY`` / ``Z402_API_URL``
    (then ``z402.DEFAULT_BASE_URL``). ``timeout`` is in seconds (default 5).

    The key is optional: with none set, the check is sent with no X-API-Key header.

    Raises, before any request: ``z402.InsecureURL`` when the URL is not https (http
    is allowed only for localhost, 127.0.0.1 and ::1), ``ValueError`` for an unknown
    list name.
    """
    kw = settings(api_key, base_url, timeout, block, interacted)

    if isinstance(client, x402ClientSync):
        cc = check_client or CheckClient(**kw)
        if not isinstance(cc, CheckClient):
            raise TypeError("x402ClientSync needs a blocking CheckClient")

        def hook_sync(ctx: Any) -> None:
            pay_to, network = _target(ctx)
            result, err = None, None
            try:
                result = cc.check(pay_to)
            except CheckUnavailable as e:
                err = e
            _apply(decide(result, err, pay_to, network, on_unavailable), on_warn, on_decision)
            return None

        client.on_before_payment_creation(hook_sync)
        return client

    if isinstance(client, x402Client):
        acc = check_client or AsyncCheckClient(**kw)
        if not isinstance(acc, AsyncCheckClient):
            raise TypeError("x402Client (async) needs an AsyncCheckClient")

        async def hook_async(ctx: Any) -> None:
            pay_to, network = _target(ctx)
            result, err = None, None
            try:
                result = await acc.check(pay_to)
            except CheckUnavailable as e:
                err = e
            _apply(decide(result, err, pay_to, network, on_unavailable), on_warn, on_decision)
            return None

        client.on_before_payment_creation(hook_async)
        return client

    raise TypeError(f"guard() needs an x402Client or x402ClientSync, got {type(client).__name__}")
