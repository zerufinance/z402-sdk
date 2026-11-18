"""Demo x402 seller on Base Sepolia with two paid routes.

    GET /ok   -> pays SELLER_OK_PAYTO   (a normal wallet)
    GET /bad  -> pays SELLER_BAD_PAYTO  (a wallet on the demo test list)

Settlement goes through the public x402 facilitator (x402.org/facilitator),
which supports Base Sepolia. Price: $0.001 testnet USDC per call.

    SELLER_OK_PAYTO=0x... SELLER_BAD_PAYTO=0x... uvicorn seller:app --port 4021
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from x402 import x402ResourceServer
from x402.http import FacilitatorConfig, HTTPFacilitatorClient
from x402.http.middleware.fastapi import payment_middleware
from x402.mechanisms.evm.exact import ExactEvmServerScheme

NETWORK = "eip155:84532"  # Base Sepolia
FACILITATOR_URL = os.getenv("FACILITATOR_URL", "https://x402.org/facilitator")

server = x402ResourceServer(HTTPFacilitatorClient(FacilitatorConfig(url=FACILITATOR_URL)))
server.register(NETWORK, ExactEvmServerScheme())

routes = {
    "GET /ok": {"accepts": {"scheme": "exact", "payTo": os.environ["SELLER_OK_PAYTO"],
                            "price": "$0.001", "network": NETWORK},
                "description": "z402 demo: normal seller"},
    "GET /bad": {"accepts": {"scheme": "exact", "payTo": os.environ["SELLER_BAD_PAYTO"],
                             "price": "$0.001", "network": NETWORK},
                 "description": "z402 demo: seller on the test list"},
}

app = FastAPI()
_mw = payment_middleware(routes, server)


@app.middleware("http")
async def x402_mw(request, call_next):
    return await _mw(request, call_next)


@app.get("/ok")
async def ok():
    return {"data": "paid content from the normal seller"}


@app.get("/bad")
async def bad():
    return {"data": "this should never be reached by a z402-guarded agent"}
