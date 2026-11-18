"""z402 demo: an agent tries to pay 5 sellers, and one seller receives a payment.
z402 asks the z402 check API about each wallet first: PAY or DON'T PAY.

Real: the check API and its live lists, read-only. Z402_API_KEY and Z402_API_URL are optional:
no key is needed. It spaces its checks out to stay under the burst guard.
Fake: the sellers and the facilitator run on this machine and the agent wallet is
brand new, so no money moves anywhere. Run it with demo.sh.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "python" / "src"), str(ROOT / "python" / "tests")]

from eth_account import Account  # noqa: E402
from x402 import x402Client, x402ResourceServer  # noqa: E402
from x402.http.clients import wrapHttpxWithPayment  # noqa: E402
from x402.mechanisms.evm.exact import ExactEvmServerScheme, register_exact_evm_client  # noqa: E402
from x402.mechanisms.evm.signers import EthAccountSigner  # noqa: E402
from x402.schemas import (PaymentRequired, PaymentRequirements, ResourceInfo,  # noqa: E402
                          SettleResponse, SupportedKind, SupportedResponse, VerifyResponse)

import z402  # noqa: E402
import fakes  # noqa: E402
from fakes import FakeSeller, dead_url  # noqa: E402

BASE = "eip155:8453"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"   # real USDC, so x402's spend controls accept it
OFAC = "0x0330070fd38ec3bb94f58fa55d40368271e9e54a"       # on the OFAC sanctions list
HACKER = "0x934147534471e9d65a313902cbefd9524af0dcf2"     # on a hacker list, no OFAC link
CLEAN = "0x9371ce1e5fdc59b5a3430d7f6b074dad1b834928"      # a brand-new wallet with no history

CASES = [
    ("Seller 1 wants to be paid to a wallet on the US sanctions list", OFAC, {}),
    ("Seller 2 wants to be paid to a wallet on a hacker list", HACKER, {}),
    ("Seller 2 again, but this agent blocks only the sanctions list", HACKER, {"block": ["sanctioned"]}),
    ("Seller 3 wants to be paid to a wallet on no list", CLEAN, {}),
    ("Seller 3 again, but the check API cannot be reached", CLEAN, {"base_url": "DEAD"}),
]


async def try_pay(pay_to: str, opts: dict) -> tuple[str, str, int, float]:
    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(Account.create()))
    seen: dict = {}
    if opts.get("base_url") == "DEAD":
        opts = {**opts, "base_url": dead_url()}
    z402.guard(client, on_decision=lambda d: seen.update(d=d), **opts)
    fakes.USDC_BASE_SEPOLIA = USDC_BASE
    t0 = time.perf_counter()
    with FakeSeller(pay_to, network=BASE) as seller:
        try:
            async with wrapHttpxWithPayment(client, timeout=10) as http:
                await http.get(f"{seller.url}/paid")
            outcome = "PAID"
        except Exception as e:  # noqa: BLE001
            outcome = "STOPPED" if z402.find_block(e) else f"ERROR {e}"
        ms = (time.perf_counter() - t0) * 1000
        d = seen.get("d")
        said = ("DON'T PAY" if d.kind == "dont_pay" else "PAY" if d.kind == "pay" else "NO ANSWER")
        said += f" ({d.result.blocked_by})" if d.result and d.result.blocked_by else ""
        return outcome, f"{said}: {d.detail}", len(seller.signatures), ms


class FakeFacilitator:
    """Counts verify/settle calls. Never touches a chain."""

    def __init__(self):
        self.verified = self.settled = 0

    def get_supported(self):
        return SupportedResponse(kinds=[SupportedKind(x402_version=2, scheme="exact", network=BASE)])

    async def verify(self, payload, requirements):
        self.verified += 1
        return VerifyResponse(is_valid=True, payer=payload.payload["authorization"]["from"])

    async def settle(self, payload, requirements):
        self.settled += 1
        return SettleResponse(success=True, transaction="0x" + "cd" * 32, network=BASE,
                              payer=payload.payload["authorization"]["from"])


async def seller_side() -> tuple[str, str, int, int]:
    """A payment arrives whose authorization says it comes from the sanctioned wallet.
    (We cannot sign as that wallet, so a fresh wallet signs and `from` is set to it;
    z402 refuses before verify, so the signature is never even looked at.)"""
    req = PaymentRequirements(scheme="exact", network=BASE, asset=USDC_BASE, amount="10000",
                              pay_to=CLEAN, max_timeout_seconds=60, extra={"name": "USD Coin", "version": "2"})
    c = x402Client()
    register_exact_evm_client(c, EthAccountSigner(Account.create()))
    payload = await c.create_payment_payload(PaymentRequired(
        x402_version=2, resource=ResourceInfo(url="http://seller/paid"), accepts=[req]))
    payload.payload["authorization"]["from"] = OFAC
    fac = FakeFacilitator()
    server = x402ResourceServer(fac)
    server.register(BASE, ExactEvmServerScheme())
    server.initialize()
    seen: dict = {}
    z402.seller_guard(server, on_decision=lambda d: seen.update(d=d))
    try:
        await server.verify_payment(payload, req)
        await server.settle_payment(payload, req)
        outcome = "ACCEPTED"
    except Exception:  # noqa: BLE001
        outcome = "REFUSED"
    d = seen["d"]
    return outcome, d.detail, fac.verified, fac.settled


async def main() -> int:
    print(f"z402 check API at {os.environ.get('Z402_API_URL', z402.DEFAULT_BASE_URL)}")
    for title, pay_to, opts in CASES:
        outcome, said, sigs, ms = await try_pay(pay_to, opts)
        print(f"\n{title}")
        print(f"  wallet  {pay_to}")
        print(f"  z402    {said}")
        print(f"  result  {outcome}  (payments signed: {sigs}, {ms:.0f} ms)")
        await asyncio.sleep(0.6)          # a short gap between checks
    outcome, said, verified, settled = await seller_side()
    print("\nSeller side: a payment arrives from the sanctioned wallet")
    print(f"  payer   {OFAC}")
    print(f"  z402    {said}")
    print(f"  result  {outcome}  (facilitator verify calls: {verified}, settle calls: {settled})")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
