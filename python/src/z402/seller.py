"""z402.seller_guard: the seller side. Check the PAYER before the money moves.

On x402 the money moves only at /settle, and the seller decides when that
happens. So a seller that screens the payer before the facilitator is asked to
verify can refuse a bad payer, and the signed authorization simply expires at
validBefore: nothing moves on chain.

    from x402 import x402ResourceServer
    import z402

    server = x402ResourceServer(facilitator_client)
    server.register(network, ExactEvmServerScheme())
    z402.seller_guard(server)      # DONT_PAY payer -> verify aborted, never settled
    z402.seller_guard(server, block=["sanctioned", "tether_frozen"])   # only these lists

Hooks: x402 2.22.0 x402ResourceServer.on_before_verify (the decision) and
on_before_settle (a second guard on the same decision, so a payment that
skipped verify is still checked). The check API is sent the payer's address
(the authorization `from`) and the chosen lists only: never the signature.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Iterable

from x402 import x402ResourceServer
from x402.schemas import AbortResult

from .check import AsyncCheckClient, CheckClient, CheckUnavailable
from .guard import Action, Decision, decide, settings

log = logging.getLogger("z402")

try:                                    # the sync server, when this x402 build has it
    from x402 import x402ResourceServerSync
except ImportError:                     # pragma: no cover
    x402ResourceServerSync = None       # type: ignore[assignment]


def payer_of(ctx: Any) -> tuple[str, str, str]:
    """(payer, network, nonce) from a verify/settle hook context. The payer is
    the EIP-3009 authorization's `from` (EVM exact). Empty when absent."""
    p = getattr(ctx.payment_payload, "payload", None) or {}
    auth = p.get("authorization") if isinstance(p, dict) else None
    auth = auth if isinstance(auth, dict) else {}
    network = str(getattr(ctx.requirements, "network", "") or "")
    return str(auth.get("from") or ""), network, str(auth.get("nonce") or "")


def _abort(d: Decision) -> AbortResult:
    by = d.result.blocked_by if d.result else None
    return AbortResult(reason=f"z402: payer {d.kind}" + (f" ({by})" if by else "") + f": {d.detail}",
                       message=f"Payment refused: {d.detail}")


def _outcome(d: Decision, on_warn, on_decision) -> AbortResult | None:
    if on_decision is not None:
        on_decision(d)
    if d.action == "pay":
        return None
    if d.action == "warn":
        (on_warn or (lambda x: log.warning("z402: accepting payer %s on %s although %s: %s",
                                           x.pay_to, x.network, x.kind, x.detail)))(d)
        return None
    return _abort(d)


def seller_guard(
    server: Any,
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
) -> Any:
    """Register the payer check on an x402 resource server; return the server.

    Same options as guard(): DONT_PAY is always refused; an unreachable check is
    refused by default (``on_unavailable="warn"`` accepts and reports it).
    """
    kw = settings(api_key, base_url, timeout, block, interacted)
    seen: dict[str, Decision] = {}     # nonce -> decision, so settle reuses verify's

    def _decide(result, err, payer, network) -> Decision:
        if not payer:
            return Decision(on_unavailable, "check_unavailable", payer, network, None,
                            "the payer address could not be read from the payment")
        return decide(result, err, payer, network, on_unavailable)

    if isinstance(server, x402ResourceServer):
        acc = check_client or AsyncCheckClient(**kw)

        async def check(ctx: Any) -> AbortResult | None:
            payer, network, nonce = payer_of(ctx)
            d = seen.get(nonce) if nonce else None
            if d is None:
                result, err = None, None
                if payer:
                    try:
                        result = await acc.check(payer)
                    except CheckUnavailable as e:
                        err = e
                d = _decide(result, err, payer, network)
                if nonce:
                    seen[nonce] = d
            return _outcome(d, on_warn, on_decision)

        server.on_before_verify(check)
        server.on_before_settle(check)
        return server

    if x402ResourceServerSync is not None and isinstance(server, x402ResourceServerSync):
        cc = check_client or CheckClient(**kw)

        def check_sync(ctx: Any) -> AbortResult | None:
            payer, network, nonce = payer_of(ctx)
            d = seen.get(nonce) if nonce else None
            if d is None:
                result, err = None, None
                if payer:
                    try:
                        result = cc.check(payer)
                    except CheckUnavailable as e:
                        err = e
                d = _decide(result, err, payer, network)
                if nonce:
                    seen[nonce] = d
            return _outcome(d, on_warn, on_decision)

        server.on_before_verify(check_sync)
        server.on_before_settle(check_sync)
        return server

    raise TypeError(f"seller_guard() needs an x402ResourceServer, got {type(server).__name__}")
