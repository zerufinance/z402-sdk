"""z402 Base Sepolia demo: the normal seller is paid, the listed seller is stopped.

Needs: a Base Sepolia wallet holding testnet USDC, its key in a file.
Spends about $0.001 testnet USDC per run.

    export AGENT_KEY_FILE=~/.config/z402-demo/agent.key    # 0x... one line, chmod 600
    export Z402_API_URL=http://127.0.0.1:8402              # the test-list stand-in
    export SELLER_URL=http://127.0.0.1:4021
    python run_demo.py   # writes demo_result.json with the transaction hash

Exit 0 only if /ok was paid (settled, tx hash present) AND /bad was stopped by
z402 with no payment header sent.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from eth_account import Account
from x402 import x402Client
from x402.http import decode_payment_response_header
from x402.http.clients import wrapHttpxWithPayment
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner

import z402

EXPLORER = "https://sepolia.basescan.org/tx/"


async def main() -> int:
    seller = os.environ.get("SELLER_URL", "http://127.0.0.1:4021").rstrip("/")
    key = Path(os.path.expanduser(os.environ["AGENT_KEY_FILE"])).read_text().strip()
    account = Account.from_key(key)
    del key
    decisions: list[dict] = []
    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(account))
    z402.guard(client, on_decision=lambda d: decisions.append(
        {"kind": d.kind, "pay_to": d.pay_to, "network": d.network, "detail": d.detail,
         "verdict": d.result.verdict if d.result else None}))

    out: dict = {"ran_at": datetime.now(timezone.utc).isoformat(), "payer": account.address,
                 "seller": seller}
    async with wrapHttpxWithPayment(client, timeout=60) as http:
        r = await http.get(seller + "/ok")
        pr = r.headers.get("PAYMENT-RESPONSE")
        settle = decode_payment_response_header(pr).model_dump(by_alias=True) if pr else None
        out["ok"] = {"status": r.status_code, "settle": settle,
                     "tx_url": EXPLORER + settle["transaction"] if settle and settle.get("transaction") else None}
        try:
            r2 = await http.get(seller + "/bad")
            out["bad"] = {"status": r2.status_code, "stopped": False,
                          "payment_response": r2.headers.get("PAYMENT-RESPONSE")}
        except Exception as e:  # noqa: BLE001
            blk = z402.find_block(e)
            if blk is None:
                raise
            out["bad"] = {"stopped": True, "verdict": blk.verdict, "kind": blk.kind,
                          "reason": blk.reason, "pay_to": blk.pay_to}
    out["decisions"] = decisions
    Path("demo_result.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    paid = out["ok"]["status"] == 200 and bool(out["ok"]["settle"] and out["ok"]["settle"].get("success"))
    stopped = out["bad"].get("stopped") is True and out["bad"].get("verdict") == "FLAGGED"
    print(f"\nnormal seller paid: {paid}   listed seller stopped: {stopped}")
    return 0 if paid and stopped else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
