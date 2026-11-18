"""z402 Python guard, end to end against a local fake seller and a fake z402 check API.

Requirements under test:
  R1 PAY -> the payment proceeds (seller receives a signed PAYMENT-SIGNATURE). The check is
     GET {base}/check/<payTo> with header X-API-Key; by default every list is blocked.
  R2 DONT_PAY -> no signature is created (signer never called, seller gets none), and the
     error carries the decision, the sentence and the list that blocked it.
  R3 block=[...] and interacted=False reach the API as ?block=a,b&interacted=false.
  R4 an unknown list name is refused when the guard is set up, before any payment.
  R5 check API down / timeout / error status / unreadable reply -> the payment stops.
  R6 the agent's private key, its signature and its own address never reach the check API.
  R7 Z402_API_URL / Z402_API_KEY are read from the environment; the default URL is the
     public HTTPS API.
  R8 the check (with or without a key) is never sent over plain http, except to
     localhost / 127.0.0.1 / ::1.
  R9 no API key (none given, or empty) -> no error at setup; the check is sent with no
     X-API-Key header at all. A refused keyless check (401/403/429) still stops the payment
     and says where to get a free key.
  R10 the default timeout (5 s) lets a slow clean verdict (about 3 s) through.
"""
from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import requests
from eth_account import Account
from x402 import x402Client, x402ClientSync, x402ResourceServer
from x402.http.clients import wrapHttpxWithPayment, wrapRequestsWithPayment
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner
from x402.schemas import PaymentAbortedError

import z402
from z402.guard import settings
from fakes import FakeCheckAPI, FakeSeller, answer, dead_url

NET = "eip155:84532"
CLEAN = "0x9371cE1E5fDC59b5A3430D7f6B074daD1b834928"
BAD = "0x1111111111111111111111111111111111111111"
API_KEY = "test_key_not_a_real_key"


class SpySigner(EthAccountSigner):
    """Real eth_account signer that counts signatures."""

    def __init__(self, account):
        super().__init__(account)
        self.calls = 0

    def sign_typed_data(self, *a, **kw):
        self.calls += 1
        return super().sign_typed_data(*a, **kw)


@pytest.fixture
def account():
    return Account.create()


@pytest.fixture
def api():
    with FakeCheckAPI() as a:
        yield a


def _async_client(account, api_url, **kw):
    signer = SpySigner(account)
    c = x402Client()
    register_exact_evm_client(c, signer)
    z402.guard(c, api_key=API_KEY, base_url=api_url, **kw)
    return c, signer


def _sync_client(account, api_url, **kw):
    signer = SpySigner(account)
    c = x402ClientSync()
    register_exact_evm_client(c, signer)
    z402.guard(c, api_key=API_KEY, base_url=api_url, **kw)
    return c, signer


async def _get_async(client, url):
    async with wrapHttpxWithPayment(client, timeout=10) as http:
        return await http.get(url)


def run_async(account, seller, api_url, **kw):
    c, signer = _async_client(account, api_url, **kw)
    try:
        r = asyncio.run(_get_async(c, f"{seller.url}/paid"))
        return r, None, signer
    except Exception as e:  # noqa: BLE001
        return None, e, signer


def run_sync(account, seller, api_url, **kw):
    c, signer = _sync_client(account, api_url, **kw)
    s = wrapRequestsWithPayment(requests.Session(), c)
    try:
        return s.get(f"{seller.url}/paid", timeout=10), None, signer
    except Exception as e:  # noqa: BLE001
        return None, e, signer


RUNNERS = [pytest.param(run_async, id="async-httpx"), pytest.param(run_sync, id="sync-requests")]


def _query(captured) -> dict[str, list[str]]:
    return parse_qs(urlsplit(captured["path"]).query, keep_blank_values=True)


# ------------------------------------------------------------------ R1 PAY pays
@pytest.mark.parametrize("run", RUNNERS)
def test_pay_payment_proceeds(run, account, api):
    api.reply = answer(CLEAN, "PAY", "This wallet is not on our sanctions or bad-wallet lists.")
    with FakeSeller(CLEAN, NET) as seller:
        r, err, signer = run(account, seller, api.url)
    assert err is None, err
    assert r.status_code == 200
    assert signer.calls == 1
    assert len(seller.signatures) == 1
    assert seller.signatures[0]["payload"]["authorization"]["to"].lower() == CLEAN.lower()
    assert len(api.captured) == 1
    req = api.captured[0]
    assert req["method"] == "GET"
    assert urlsplit(req["path"]).path == f"/check/{CLEAN}"
    assert req["headers"].get("X-API-Key") == API_KEY
    assert _query(req) == {"hops": ["1"], "contracts": ["1"]}   # default: every list, direct contact only
    assert req["raw"] == b""


# ------------------------------------------------------ R2 DONT_PAY, no signature
@pytest.mark.parametrize("run", RUNNERS)
def test_dont_pay_creates_no_signature(run, account, api):
    sentence = "This wallet is on a list of phishing wallets."
    api.reply = answer(BAD, "DONT_PAY", sentence, "phishing")
    with FakeSeller(BAD, NET) as seller:
        r, err, signer = run(account, seller, api.url)
    assert r is None
    blk = z402.find_block(err)
    assert blk is not None, repr(err)
    assert blk.kind == "dont_pay" and blk.verdict == "FLAGGED"
    assert blk.reason == sentence
    assert blk.blocked_by == "phishing"
    assert blk.pay_to == BAD and blk.network == NET
    assert "DON'T PAY" in str(blk) and sentence in str(blk)
    assert signer.calls == 0
    assert seller.signatures == []
    assert seller.requests == 1          # only the first unpaid GET


def test_raised_error_is_an_x402_abort(account, api):
    """Without an HTTP wrapper, create_payment_payload raises Z402Blocked itself."""
    from x402.schemas import PaymentRequired, PaymentRequirements
    api.reply = answer(BAD, "DONT_PAY", "This wallet is on the OFAC sanctions list.", "sanctioned")
    c, signer = _async_client(account, api.url)
    pr = PaymentRequired(x402_version=2, accepts=[PaymentRequirements(
        scheme="exact", network=NET, asset="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        amount="10000", pay_to=BAD, max_timeout_seconds=60,
        extra={"name": "USDC", "version": "2"})])
    with pytest.raises(z402.Z402Blocked) as ei:
        asyncio.run(c.create_payment_payload(pr))
    assert isinstance(ei.value, PaymentAbortedError)
    assert signer.calls == 0


def test_dont_pay_cannot_be_relaxed(account, api):
    """'warn' only applies to an unavailable check; DONT_PAY always stops."""
    api.reply = answer(BAD, "DONT_PAY", "Sanctioned.", "sanctioned")
    with FakeSeller(BAD, NET) as seller:
        _, err, signer = run_async(account, seller, api.url, on_unavailable="warn")
    assert z402.find_block(err).kind == "dont_pay"
    assert signer.calls == 0 and seller.signatures == []


# ---------------------------------------------------- R3 options reach the API
@pytest.mark.parametrize("run", RUNNERS)
def test_block_and_interacted_are_sent(run, account, api):
    api.reply = answer(CLEAN, "PAY", "Nothing found on the lists you chose to block.")
    with FakeSeller(CLEAN, NET) as seller:
        r, err, _ = run(account, seller, api.url, block=["sanctioned", "scams"], interacted=False)
    assert err is None and r.status_code == 200
    q = _query(api.captured[0])
    assert q["block"][0].split(",") == ["sanctioned", "scams"]
    assert q["interacted"] == ["false"]


@pytest.mark.parametrize("run", RUNNERS)
def test_direct_contact_only_is_sent(run, account, api):
    # Contact counts only when the wallet dealt with a listed wallet itself.
    api.reply = answer(CLEAN, "PAY", "fine")
    with FakeSeller(CLEAN, NET) as seller:
        r, err, _ = run(account, seller, api.url)
    assert err is None and r.status_code == 200
    assert _query(api.captured[0]).get("hops") == ["1"]


@pytest.mark.parametrize("run", RUNNERS)
def test_contracts_are_never_flagged_for_contact_is_asked(run, account, api):
    # A contract, exchange or DEX is never FLAGGED only for contact.
    api.reply = answer(CLEAN, "PAY", "fine")
    with FakeSeller(CLEAN, NET) as seller:
        r, err, _ = run(account, seller, api.url)
    assert err is None and r.status_code == 200
    assert _query(api.captured[0]).get("contracts") == ["1"]


def test_all_lists_same_as_default(account, api):
    api.reply = answer(CLEAN, "PAY", "fine")
    with FakeSeller(CLEAN, NET) as seller:
        run_async(account, seller, api.url, block=list(z402.GROUPS))
    q = _query(api.captured[0])
    assert set(q.get("block", [",".join(z402.GROUPS)])[0].split(",")) == set(z402.GROUPS)
    assert "interacted" not in q or q["interacted"] == ["true"]


# ------------------------------------------------------ R4 bad list names
@pytest.mark.parametrize("block", [["sanctioned", "nope"], [], "sanctioned"])
def test_unknown_or_empty_block_refused_at_setup(block):
    c = x402Client()
    with pytest.raises(ValueError):
        z402.guard(c, block=block, api_key=API_KEY, base_url="http://127.0.0.1:9")


# ------------------------------------------------------------- R5 API failures
@pytest.mark.parametrize("run", RUNNERS)
def test_api_down_stops(run, account):
    with FakeSeller(CLEAN, NET) as seller:
        r, err, signer = run(account, seller, dead_url())
    blk = z402.find_block(err)
    assert blk is not None, repr(err)
    assert blk.kind == "check_unavailable" and blk.verdict is None
    assert signer.calls == 0 and seller.signatures == []


# The error answers the public API gives (status and body as the server sends them).
@pytest.mark.parametrize("status,body", [
    (500, {"error": "Something went wrong."}),
    (502, {"error": "The check is not available right now. Try again in a minute."}),
    (401, {"error": "This API key is not valid. Create one in your developer dashboard."}),
    (403, {"error": "This key cannot check."}),
    (429, {"error": "Too many checks: the Free plan allows 2 a second for each key."}),
    (429, {"error": "You used all 100 verdicts on the free plan this month."}),
    (400, {"error": "This is not a wallet address we recognise."}),
    (400, {"error": "Unknown list: nope. Valid lists: sanctioned, scams."}),
    (200, {"verdict": "MAYBE", "decision": "MAYBE", "sentence": "x"}),
    (200, {"verdict": "CLEAR", "decision": "PAY"}),                         # no sentence
    (200, {"verdict": "FLAGGED", "decision": "PAY", "sentence": "x"}),      # contradicts itself
    (200, ["not", "an", "object"]),
])
def test_bad_api_reply_stops(status, body, account, api):
    api.status, api.reply = status, body
    with FakeSeller(CLEAN, NET) as seller:
        _, err, signer = run_async(account, seller, api.url)
    assert z402.find_block(err).kind == "check_unavailable"
    assert signer.calls == 0 and seller.signatures == []


def test_api_timeout_stops(account, api):
    api.reply = answer(CLEAN, "PAY", "fine")
    api.delay_s = 1.0
    with FakeSeller(CLEAN, NET) as seller:
        _, err, signer = run_sync(account, seller, api.url, timeout=0.2)
    assert z402.find_block(err).kind == "check_unavailable"
    assert signer.calls == 0 and seller.signatures == []


def test_api_down_warn_mode_pays_and_reports(account):
    seen = []
    with FakeSeller(CLEAN, NET) as seller:
        r, err, signer = run_async(account, seller, dead_url(), on_unavailable="warn",
                                   on_warn=seen.append)
    assert err is None and r.status_code == 200
    assert [d.kind for d in seen] == ["check_unavailable"]
    assert signer.calls == 1


# ------------------------------------------------------ R6 key never sent
@pytest.mark.parametrize("run", RUNNERS)
def test_private_key_never_sent_to_check_api(run, account, api):
    api.reply = answer(CLEAN, "PAY", "fine")
    with FakeSeller(CLEAN, NET) as seller:
        r, err, _ = run(account, seller, api.url)
    assert err is None and r.status_code == 200
    key_hex = account.key.hex().lower().removeprefix("0x")
    assert len(key_hex) == 64
    sig = seller.signatures[0]["payload"]["signature"].lower().removeprefix("0x")
    assert len(api.captured) == 1
    for req in api.captured:
        blob = (req["path"].encode() + req["raw"] + json.dumps(req["headers"]).encode()).lower()
        assert key_hex.encode() not in blob
        assert sig.encode() not in blob            # no signature either: check runs before signing
        assert account.address.lower().removeprefix("0x").encode() not in blob   # nor the payer
        assert req["raw"] == b""


@pytest.mark.parametrize("status,raw,headers", [
    (404, b"<html>not found</html>", {}),                       # wrong host or path: an HTML page
    (502, b"<html>bad gateway</html>", {}),                     # a proxy error page
    (302, b"", {"Location": "http://127.0.0.1:9/elsewhere"}),   # a redirect is never followed
])
def test_non_json_or_redirect_stops(status, raw, headers, account, api):
    api.status, api.raw_reply, api.extra_headers = status, raw, headers
    with FakeSeller(CLEAN, NET) as seller:
        _, err, signer = run_async(account, seller, api.url)
    assert z402.find_block(err).kind == "check_unavailable"
    assert signer.calls == 0 and seller.signatures == []
    assert len(api.captured) == 1          # asked once; a redirect was not followed


@pytest.mark.parametrize("status", [401, 403])
def test_key_refused_says_where_to_get_one(status, account, api):
    api.status, api.reply = status, {"error": "This API key is not valid."}
    with FakeSeller(CLEAN, NET) as seller:
        _, err, _ = run_async(account, seller, api.url)
    blk = z402.find_block(err)
    assert blk.kind == "check_unavailable"
    assert "Z402_API_KEY" in blk.reason and z402.KEY_URL in blk.reason


# ------------------------------------------------------ R7 environment
def test_env_vars_and_default_url(account, api, monkeypatch):
    assert z402.DEFAULT_BASE_URL == "https://zscreen-api.zeruai.org"
    monkeypatch.setenv("Z402_API_URL", api.url)
    monkeypatch.setenv("Z402_API_KEY", "from_env_key")
    api.reply = answer(CLEAN, "PAY", "fine")
    signer = SpySigner(account)
    c = x402Client()
    register_exact_evm_client(c, signer)
    z402.guard(c)
    with FakeSeller(CLEAN, NET) as seller:
        r = asyncio.run(_get_async(c, f"{seller.url}/paid"))
    assert r.status_code == 200
    assert api.captured[0]["headers"].get("X-API-Key") == "from_env_key"


# ------------------------------------------------------ decision table (pure)
def test_decide_table():
    R = lambda d: z402.CheckResult(address=CLEAN, decision=d,
                                   verdict="FLAGGED" if d == "DONT_PAY" else "CLEAR",
                                   sentence="s", blocked_by="scams" if d == "DONT_PAY" else None)
    assert z402.decide(R("PAY"), None, CLEAN, NET).action == "pay"
    assert z402.decide(R("DONT_PAY"), None, CLEAN, NET).action == "stop"
    assert z402.decide(None, RuntimeError("x"), CLEAN, NET).action == "stop"
    assert z402.decide(None, RuntimeError("x"), CLEAN, NET, on_unavailable="warn").action == "warn"


def test_guard_rejects_wrong_client():
    with pytest.raises(TypeError):
        z402.guard(object(), api_key=API_KEY)
    with pytest.raises(TypeError):
        z402.guard(x402ClientSync(), check_client=z402.AsyncCheckClient(api_key=API_KEY))


def test_default_url_is_used_when_nothing_is_set(monkeypatch):
    """No base_url and no Z402_API_URL: the request goes to the public HTTPS API.
    A mock transport answers, so nothing leaves this machine."""
    monkeypatch.delenv("Z402_API_URL", raising=False)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=answer(CLEAN, "PAY", "fine"))

    kw = settings(API_KEY, None, None, None, True)
    assert kw["base_url"] == "https://zscreen-api.zeruai.org"
    r = z402.CheckClient(**kw, transport=httpx.MockTransport(handler)).check(CLEAN)
    assert r.decision == "PAY"
    assert str(seen[0].url).startswith(f"https://zscreen-api.zeruai.org/check/{CLEAN}?")
    assert seen[0].headers["X-API-Key"] == API_KEY


# ------------------------------------------------------ R8 https only for the key
INSECURE = ["http://zscreen-api.zeruai.org", "http://10.0.0.1:8090", "http://example.com",
            "http://127.0.0.1.example.com", "http://localhost@example.com",
            "http://localhost.example.com", "ftp://localhost", "zscreen-api.zeruai.org", "https://"]
SAFE = ["http://localhost:8402", "http://127.0.0.1:8402", "http://[::1]:8402", "HTTP://LOCALHOST:1/",
        "https://zscreen-api.zeruai.org", "https://example.com:8443/base/"]


@pytest.mark.parametrize("url", INSECURE)
def test_insecure_url_refused_at_setup(url):
    for client in (x402Client(), x402ClientSync()):
        with pytest.raises(z402.InsecureURL) as ei:
            z402.guard(client, api_key=API_KEY, base_url=url)
        assert "https" in str(ei.value)
    with pytest.raises(z402.InsecureURL):
        z402.seller_guard(x402ResourceServer(object()), api_key=API_KEY, base_url=url)
    with pytest.raises(z402.InsecureURL):
        z402.CheckClient(api_key=API_KEY, base_url=url)
    with pytest.raises(z402.InsecureURL):
        z402.AsyncCheckClient(api_key=API_KEY, base_url=url)


@pytest.mark.parametrize("url", SAFE)
def test_https_and_localhost_accepted(url):
    z402.guard(x402Client(), api_key=API_KEY, base_url=url)
    assert z402.CheckClient(api_key=API_KEY, base_url=url).base_url == url.rstrip("/")


def test_insecure_url_from_env_refused(monkeypatch):
    monkeypatch.setenv("Z402_API_URL", "http://example.com")
    with pytest.raises(z402.InsecureURL):
        z402.guard(x402Client(), api_key=API_KEY)
    with pytest.raises(z402.InsecureURL):
        z402.seller_guard(x402ResourceServer(object()), api_key=API_KEY)


def test_key_not_sent_if_url_is_changed_to_http_later():
    """A client whose base_url is changed after it was made still never sends the key over http."""
    seen = []
    cc = z402.CheckClient(api_key=API_KEY, transport=httpx.MockTransport(seen.append))
    cc.base_url = "http://example.com"
    with pytest.raises(z402.InsecureURL):
        cc.check(CLEAN)
    assert seen == []


# ------------------------------------------------------ R9 no key
# (key argument, Z402_API_KEY): every way of having no key.
NO_KEY = [pytest.param(None, None, id="no-arg-no-env"), pytest.param("", None, id="empty-arg"),
          pytest.param("   ", None, id="blank-arg"), pytest.param(None, "", id="empty-env"),
          pytest.param(None, "   ", id="blank-env")]


def _set_env_key(monkeypatch, env):
    if env is None:
        monkeypatch.delenv("Z402_API_KEY", raising=False)
    else:
        monkeypatch.setenv("Z402_API_KEY", env)


def _sent_key_header(req) -> bool:
    return any(k.lower() == "x-api-key" for k in req["headers"])


@pytest.mark.parametrize("key,env", NO_KEY)
@pytest.mark.parametrize("cls", [pytest.param(x402Client, id="async"),
                                 pytest.param(x402ClientSync, id="sync")])
def test_no_key_pays_and_sends_no_key_header(cls, key, env, account, api, monkeypatch):
    _set_env_key(monkeypatch, env)
    api.reply = answer(CLEAN, "PAY", "fine")
    signer = SpySigner(account)
    c = cls()
    register_exact_evm_client(c, signer)
    z402.guard(c, api_key=key, base_url=api.url)          # no error at setup
    with FakeSeller(CLEAN, NET) as seller:
        if cls is x402Client:
            r = asyncio.run(_get_async(c, f"{seller.url}/paid"))
        else:
            r = wrapRequestsWithPayment(requests.Session(), c).get(f"{seller.url}/paid", timeout=10)
    assert r.status_code == 200
    assert signer.calls == 1 and len(seller.signatures) == 1
    assert len(api.captured) == 1
    assert not _sent_key_header(api.captured[0]), api.captured[0]["headers"]


@pytest.mark.parametrize("key,env", NO_KEY)
def test_no_key_check_clients_send_no_key_header(key, env, api, monkeypatch):
    _set_env_key(monkeypatch, env)
    api.reply = answer(CLEAN, "PAY", "fine")
    assert z402.CheckClient(api_key=key, base_url=api.url).check(CLEAN).decision == "PAY"
    r = asyncio.run(z402.AsyncCheckClient(api_key=key, base_url=api.url).check(CLEAN))
    assert r.decision == "PAY"
    assert len(api.captured) == 2
    assert not any(_sent_key_header(c) for c in api.captured)
    # The old error class is still importable, so code that catches it keeps working.
    assert issubclass(z402.MissingAPIKey, ValueError)


@pytest.mark.parametrize("status,body", [
    (401, {"error": "An API key is required."}),
    (403, {"error": "This check is not allowed."}),
    (429, {"error": "Too many checks at once. Slow down, or create a free key."}),
])
def test_no_key_refused_stops_and_says_where_to_get_a_free_key(status, body, account, api,
                                                              monkeypatch):
    monkeypatch.delenv("Z402_API_KEY", raising=False)
    api.status, api.reply = status, body
    signer = SpySigner(account)
    c = x402Client()
    register_exact_evm_client(c, signer)
    z402.guard(c, base_url=api.url)
    with FakeSeller(CLEAN, NET) as seller:
        try:
            asyncio.run(_get_async(c, f"{seller.url}/paid"))
            err = None
        except Exception as e:  # noqa: BLE001
            err = e
    blk = z402.find_block(err)
    assert blk is not None and blk.kind == "check_unavailable", repr(err)
    assert signer.calls == 0 and seller.signatures == []
    assert z402.KEY_URL in blk.reason and "Z402_API_KEY" in blk.reason, blk.reason
    assert body["error"] in blk.reason


@pytest.mark.parametrize("url", INSECURE)
def test_insecure_url_refused_without_a_key_too(url, monkeypatch):
    monkeypatch.delenv("Z402_API_KEY", raising=False)
    for client in (x402Client(), x402ClientSync()):
        with pytest.raises(z402.InsecureURL):
            z402.guard(client, base_url=url)
    with pytest.raises(z402.InsecureURL):
        z402.seller_guard(x402ResourceServer(object()), base_url=url)
    with pytest.raises(z402.InsecureURL):
        z402.CheckClient(base_url=url)
    with pytest.raises(z402.InsecureURL):
        z402.AsyncCheckClient(base_url=url)


# ------------------------------------------------------ R10 timeout
def test_default_timeout_is_5s():
    assert z402.DEFAULT_TIMEOUT_S == 5.0
    assert z402.CheckClient(api_key=API_KEY).timeout == 5.0
    assert z402.AsyncCheckClient(api_key=API_KEY).timeout == 5.0
    assert z402.CheckClient(api_key=API_KEY, timeout=1.5).timeout == 1.5


@pytest.mark.parametrize("run", RUNNERS)
def test_slow_clean_verdict_pays_with_default_timeout(run, account, api):
    """A clear verdict that takes 2.5 s (over the old 2 s default) still pays."""
    api.reply = answer(CLEAN, "PAY", "fine")
    api.delay_s = 2.5
    with FakeSeller(CLEAN, NET) as seller:
        r, err, signer = run(account, seller, api.url)
    assert err is None, err
    assert r.status_code == 200 and signer.calls == 1
