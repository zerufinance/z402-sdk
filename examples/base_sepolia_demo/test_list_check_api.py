"""Demo-only stand-in for the z402 check API (GET /check/<address>), driven by a test list file.

Use it on the Base Sepolia testnet, where the real lists hold no addresses. It answers
in the same shape as the z402 check API:
  - address in TEST_LIST_FILE -> FLAGGED / DONT_PAY, blocked_by "scams"
  - anything else             -> CLEAR / PAY
This is NOT zScreen and makes no real judgement. Local only.

    TEST_LIST_FILE=test_list.txt uvicorn test_list_check_api:app --port 8402
"""
from __future__ import annotations

import os

from fastapi import FastAPI

app = FastAPI()


def _listed() -> set[str]:
    path = os.environ.get("TEST_LIST_FILE", "test_list.txt")
    with open(path) as f:
        return {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}


@app.get("/check/{address}")
async def check(address: str):
    if address.lower() in _listed():
        return {"address": address, "chain": "base-sepolia", "verdict": "FLAGGED",
                "sentence": "This wallet is on the z402 demo test list.", "decision": "DONT_PAY",
                "blocked_by": "scams"}
    return {"address": address, "chain": "base-sepolia", "verdict": "CLEAR",
            "sentence": "Not on the z402 demo test list.", "decision": "PAY"}
