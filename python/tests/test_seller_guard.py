"""z402.seller_guard: the seller checks the PAYER before the payment is settled.

The requirement: when a wallet is bad the payment must be stopped, both ways,
judged by the z402 check API (DONT_PAY / PAY) with the seller's chosen lists. On the seller side the money only moves at
/settle, so a DONT_PAY payer must be refused before the facilitator is asked to
verify or settle; a PAY payer is settled as normal; an unavailable check refuses.
The checked wallet is the payer (the authorization `from`). The check API gets
the payer's address only: never the signature.

A real x402 2.22.0 x402ResourceServer, a real client-signed EIP-3009 payload,
a fake facilitator that counts calls, and the local fake check API.
"""
from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from eth_account import Account
from x402 import x402Client, x402ResourceServer
from x402.mechanisms.evm.exact import ExactEvmServerScheme, register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner
from x402.schemas import (PaymentAbortedError, PaymentRequired, PaymentRequirements,
                          ResourceInfo, SettleResponse, SupportedKind, SupportedResponse,
                          VerifyResponse)

import z402
from fakes import FakeCheckAPI, answer

NET = "eip155:84532"
USDC_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
SELLER = "0x" + "5e" * 20


class FakeFacilitator:
    def __init__(self):
        self.verified = 0
        self.settled = 0

    def get_supported(self):
        return SupportedResponse(kinds=[SupportedKind(x402_version=2, scheme="exact",
                                                      network=NET)])

    async def verify(self, payload, requirements):
        self.verified += 1
        return VerifyResponse(is_valid=True, payer=payload.payload["authorization"]["from"])

    async def settle(self, payload, requirements):
        self.settled += 1
        return SettleResponse(success=True, transaction="0x" + "cd" * 32, network=NET,
                              payer=payload.payload["authorization"]["from"])


def _requirements():
    return PaymentRequirements(scheme="exact", network=NET, asset=USDC_SEPOLIA,
                               amount="10000", pay_to=SELLER, max_timeout_seconds=60,
                               extra={"name": "USDC", "version": "2"})


async def _signed_payload(account):
    c = x402Client()
    register_exact_evm_client(c, EthAccountSigner(account))
    pr = PaymentRequired(x402_version=2, resource=ResourceInfo(url="http://s/paid"),
                         accepts=[_requirements()])
    return await c.create_payment_payload(pr)


def _server(api, api_key="test_key", **kw):
    fac = FakeFacilitator()
    s = x402ResourceServer(fac)
    s.register(NET, ExactEvmServerScheme())
    s.initialize()
    z402.seller_guard(s, api_key=api_key, base_url=api.url, **kw)
    return s, fac


async def _verify_then_settle(server, payload):
    req = _requirements()
    await server.verify_payment(payload, req)
    return await server.settle_payment(payload, req)


@pytest.fixture
def api():
    with FakeCheckAPI() as a:
        yield a


def _checked(api):
    return [urlsplit(c["path"]) for c in api.captured]


def test_dont_pay_payer_is_refused_before_verify_and_never_settled(api):
    acct = Account.create()
    api.reply = answer(acct.address, "DONT_PAY", "This wallet was frozen by Tether (USDT).",
                       "tether_frozen")
    server, fac = _server(api)
    payload = asyncio.run(_signed_payload(acct))
    with pytest.raises(PaymentAbortedError) as e:
        asyncio.run(_verify_then_settle(server, payload))
    assert fac.verified == 0 and fac.settled == 0
    assert "frozen by Tether" in str(e.value.reason)
    # the wallet checked is the payer (authorization `from`), not the seller
    assert _checked(api)[0].path == f"/check/{acct.address}"
    assert api.captured[0]["headers"].get("X-API-Key") == "test_key"


def test_pay_payer_is_settled(api):
    acct = Account.create()
    api.reply = answer(acct.address, "PAY", "Nothing found on the lists you chose to block.")
    server, fac = _server(api)
    payload = asyncio.run(_signed_payload(acct))
    res = asyncio.run(_verify_then_settle(server, payload))
    assert res.success and fac.verified == 1 and fac.settled == 1


def test_seller_block_options_are_sent(api):
    acct = Account.create()
    api.reply = answer(acct.address, "PAY", "Nothing found on the lists you chose to block.")
    server, fac = _server(api, block=["sanctioned", "ransomware"], interacted=False)
    asyncio.run(_verify_then_settle(server, asyncio.run(_signed_payload(acct))))
    q = parse_qs(_checked(api)[0].query)
    assert q["block"][0].split(",") == ["sanctioned", "ransomware"]
    assert q["interacted"] == ["false"]
    assert fac.settled == 1


def test_seller_unknown_list_refused_at_setup(api):
    with pytest.raises(ValueError):
        _server(api, block=["hackers", "not_a_list"])


@pytest.mark.parametrize("status", [500, 502, 401, 403, 429, 400])
def test_check_api_error_stops(api, status):
    acct = Account.create()
    api.status, api.reply = status, {"error": "x"}
    server, fac = _server(api)
    with pytest.raises(PaymentAbortedError):
        asyncio.run(_verify_then_settle(server, asyncio.run(_signed_payload(acct))))
    assert fac.verified == 0 and fac.settled == 0


def test_check_api_down_stops(api):
    acct = Account.create()
    server, fac = _server(api, timeout=0.2)
    api.delay_s = 1.0
    api.reply = answer(acct.address, "PAY", "x")
    with pytest.raises(PaymentAbortedError):
        asyncio.run(_verify_then_settle(server, asyncio.run(_signed_payload(acct))))
    assert fac.settled == 0


def test_signature_is_never_sent_to_the_check_api(api):
    acct = Account.create()
    api.reply = answer(acct.address, "PAY", "x")
    server, _ = _server(api)
    payload = asyncio.run(_signed_payload(acct))
    asyncio.run(_verify_then_settle(server, payload))
    sig = payload.payload["signature"].lower().removeprefix("0x")
    assert api.captured
    for c in api.captured:
        raw = (c["path"] + c["raw"].decode() + json.dumps(c["headers"])).lower()
        assert sig not in raw and acct.key.hex().removeprefix("0x") not in raw
        assert c["raw"] == b""


@pytest.mark.parametrize("key", [None, "", "   "])
def test_no_key_payer_is_checked_without_a_key_header_and_settled(key, api, monkeypatch):
    """No key at all: no error at setup, the payer is still checked (with no X-API-Key
    header), and a PAY payer is verified and settled."""
    monkeypatch.delenv("Z402_API_KEY", raising=False)
    acct = Account.create()
    api.reply = answer(acct.address, "PAY", "Nothing found on the lists you chose to block.")
    server, fac = _server(api, api_key=key)
    payload = asyncio.run(_signed_payload(acct))
    asyncio.run(_verify_then_settle(server, payload))
    assert fac.verified == 1 and fac.settled == 1
    assert _checked(api)[0].path == f"/check/{acct.address}"
    assert not any(k.lower() == "x-api-key" for c in api.captured for k in c["headers"])
