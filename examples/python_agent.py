"""Example agent (Python): pay an x402 URL, with z402 checking the payTo first.

    pip install "zeru-z402" "x402[httpx,evm]"
    export Z402_API_KEY=...                            # optional; free key: https://zscreen.zeruai.org/app
    export AGENT_KEY_FILE=~/.config/agent/evm.key      # one line, 0x... private key
    python examples/python_agent.py https://seller.example/paid

The private key is read here, given to the x402 signer, and nowhere else.
z402 only sends the seller's payTo address (and the lists you block) to the z402 check API.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from eth_account import Account
from x402 import x402Client
from x402.http.clients import wrapHttpxWithPayment
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner

import z402


async def main(url: str) -> int:
    key = Path(os.path.expanduser(os.environ["AGENT_KEY_FILE"])).read_text().strip()
    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(Account.from_key(key)))
    del key

    z402.guard(
        client,
        # block=["sanctioned", "scams"],   # default: every list in z402.GROUPS
        on_decision=lambda d: print(f"z402: {d.kind} {d.pay_to} on {d.network}: {d.detail}"),
    )

    async with wrapHttpxWithPayment(client, timeout=30) as http:
        try:
            r = await http.get(url)
        except Exception as e:  # noqa: BLE001
            blk = z402.find_block(e)
            if blk is None:
                raise
            print(f"NOT PAID ({blk.blocked_by or blk.kind}): {blk.reason}")
            return 2
    print(f"HTTP {r.status_code}; PAYMENT-RESPONSE: {r.headers.get('PAYMENT-RESPONSE', '-')[:60]}")
    print(r.text[:500])
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1])))
