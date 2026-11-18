"""The call to the z402 check API, and the shape of its answer.

    GET {base}/check/<address>?block=sanctioned,scams&interacted=false
    X-API-Key: <key>          (only when a key is set)

    200 -> {"address", "chain", "verdict": "FLAGGED"|"CLEAR", "sentence",
            "decision": "DONT_PAY"|"PAY", "blocked_by": <list> (only on DONT_PAY)}
    400 / 401 / 403 / 429 / 5xx -> {"error": "<one sentence>"}

Any answer other than a well-formed 200 raises CheckUnavailable, so the payment
stops (fail closed). Only the wallet address and the chosen lists are sent.
Nothing from the agent's wallet or signer is ever passed to this module.

The API key is optional. With no key, no X-API-Key header is sent and the API
answers the same way. The API allows 1,000 checks in total for each IP address without
a key (never reset), or 1,000 a month for each account with a key, plus a burst guard
of about 5 checks a second, and answers 429 over a limit.
A free key is made at KEY_URL.

Every check goes over HTTPS, with or without a key. Plain http is accepted for
localhost, 127.0.0.1 and ::1 only (a local test server); any other http URL is
refused before a request is made.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import quote, urlsplit

import httpx

DEFAULT_BASE_URL = "https://zscreen-api.zeruai.org"
KEY_URL = "https://zscreen.zeruai.org/app"     # where a free API key is made
CHECK_PATH = "/check/"
# The lists a caller can block. Default: all of them.
GROUPS = ("sanctioned", "tether_frozen", "circle_frozen", "hackers", "scams", "phishing",
          "ransomware", "terror_financing", "mixers")
DECISION_OF = {"FLAGGED": "DONT_PAY", "CLEAR": "PAY"}
# A clear verdict can take about 3 s, so the default leaves room for it.
DEFAULT_TIMEOUT_S = 5.0
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class CheckUnavailable(Exception):
    """The check API could not give a usable answer (down, timeout, error, bad reply)."""


class MissingAPIKey(ValueError):
    """No longer raised: the API key is optional (no key = a keyless check).

    Kept so code that imports or catches it keeps working.
    """

    def __init__(self) -> None:
        super().__init__("z402 needs an API key. Set Z402_API_KEY (or pass api_key=...). "
                         f"Get a free key at {KEY_URL}")


class InsecureURL(ValueError):
    """The check API URL is not HTTPS (and not localhost). Raised before any request is made."""


def require_safe_url(url: str) -> str:
    """Return ``url`` without a trailing slash if a check may be sent to it, else raise InsecureURL.

    https:// to any host is allowed. http:// only to localhost, 127.0.0.1 or ::1.
    """
    try:
        parts = urlsplit(str(url))
        host = (parts.hostname or "").lower()
    except ValueError as e:
        raise InsecureURL(f"z402 check API URL is not a valid URL: {url!r}") from e
    scheme = parts.scheme.lower()
    if scheme == "https" and host:
        return str(url).rstrip("/")
    if scheme == "http" and host in LOCAL_HOSTS:
        return str(url).rstrip("/")
    raise InsecureURL(f"z402 refuses to send the check to {url!r}: use an https:// URL "
                      "(plain http is allowed only for localhost, 127.0.0.1 and ::1)")


def optional_key(api_key: str | None) -> str | None:
    """The key to send, or None (no key, empty or only spaces) for a keyless check."""
    if not api_key or not str(api_key).strip():
        return None
    return str(api_key)


def normalize_block(block: Iterable[str] | None) -> tuple[str, ...] | None:
    """None -> None (every list). Otherwise the names, checked. Unknown or empty -> ValueError."""
    if block is None:
        return None
    if isinstance(block, (str, bytes)):
        raise ValueError('block must be a list of names, e.g. block=["sanctioned", "scams"]')
    names = tuple(dict.fromkeys(str(b).strip().lower() for b in block))
    if not names:
        raise ValueError("block is empty: choose at least one of " + ", ".join(GROUPS))
    bad = [n for n in names if n not in GROUPS]
    if bad:
        raise ValueError("unknown block list " + ", ".join(bad) + ". Valid: " + ", ".join(GROUPS))
    return names


def check_path(address: str, block: tuple[str, ...] | None, interacted: bool) -> str:
    q = []
    if block is not None and set(block) != set(GROUPS):
        q.append("block=" + ",".join(block))
    if not interacted:
        q.append("interacted=false")
    else:
        q.append("hops=1")        # contact counts only when the wallet dealt with a listed wallet itself
        q.append("contracts=1")   # a contract, exchange or DEX is never FLAGGED only for contact
    return CHECK_PATH + quote(address, safe=":") + ("?" + "&".join(q) if q else "")


@dataclass(frozen=True)
class CheckResult:
    address: str
    decision: str                 # "DONT_PAY" | "PAY"
    verdict: str                  # "FLAGGED" | "CLEAR"
    sentence: str
    blocked_by: str | None = None
    chain: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_body(cls, body: Any) -> "CheckResult":
        if not isinstance(body, dict):
            raise CheckUnavailable("check API returned a non-object body")
        verdict = body.get("verdict")
        if verdict not in DECISION_OF:
            raise CheckUnavailable(f"check API returned an unknown verdict {verdict!r}")
        decision = body.get("decision", DECISION_OF[verdict])
        if decision != DECISION_OF[verdict]:
            raise CheckUnavailable(f"check API answer contradicts itself ({verdict} / {decision!r})")
        sentence = body.get("sentence")
        if not isinstance(sentence, str) or not sentence:
            raise CheckUnavailable("check API returned no sentence")
        return cls(address=str(body.get("address", "")), decision=decision, verdict=verdict,
                   sentence=sentence, blocked_by=body.get("blocked_by"), chain=body.get("chain"),
                   raw=body)


def _headers(api_key: str | None) -> dict[str, str]:
    h = {"Accept": "application/json"}
    if api_key is not None:            # no key: no header at all, not an empty one
        h["X-API-Key"] = api_key
    return h


def _hint(status: int, keyed: bool) -> str:
    """What to do about a refused check: fix the key, or where to get one."""
    if keyed:
        return f" (check Z402_API_KEY; get a free key at {KEY_URL})" if status in (401, 403) else ""
    if status in (401, 403, 429):
        return f" (no API key set; get a free key at {KEY_URL} and set Z402_API_KEY)"
    return ""


def _parse(r: httpx.Response, keyed: bool) -> CheckResult:
    if r.status_code != 200:
        try:
            why = r.json().get("error")
        except Exception:  # noqa: BLE001
            why = None
        hint = _hint(r.status_code, keyed)
        raise CheckUnavailable(f"check API answered HTTP {r.status_code}" + (f": {why}" if why else "") + hint)
    try:
        body = r.json()
    except ValueError as e:
        raise CheckUnavailable("check API returned non-JSON") from e
    return CheckResult.from_body(body)


class CheckClient:
    """Blocking client. Used by the x402ClientSync guard.

    ``api_key`` is optional (None = a keyless check).
    Raises InsecureURL when it is made, before any request.
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL, api_key: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT_S, block: Iterable[str] | None = None,
                 interacted: bool = True, transport: httpx.BaseTransport | None = None) -> None:
        self.base_url = require_safe_url(base_url)
        self._api_key = optional_key(api_key)
        self.timeout = timeout
        self.block = normalize_block(block)
        self.interacted = interacted
        self._transport = transport

    def check(self, address: str) -> CheckResult:
        url = require_safe_url(self.base_url) + check_path(address, self.block, self.interacted)
        try:
            with httpx.Client(timeout=self.timeout, transport=self._transport,
                              follow_redirects=False) as c:
                r = c.get(url, headers=_headers(self._api_key))
        except httpx.HTTPError as e:
            raise CheckUnavailable(f"could not reach the z402 check API: {type(e).__name__}") from e
        return _parse(r, self._api_key is not None)


class AsyncCheckClient:
    """Async client. Used by the x402Client (async) guard.

    ``api_key`` is optional (None = a keyless check).
    Raises InsecureURL when it is made, before any request.
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL, api_key: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT_S, block: Iterable[str] | None = None,
                 interacted: bool = True, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.base_url = require_safe_url(base_url)
        self._api_key = optional_key(api_key)
        self.timeout = timeout
        self.block = normalize_block(block)
        self.interacted = interacted
        self._transport = transport

    async def check(self, address: str) -> CheckResult:
        url = require_safe_url(self.base_url) + check_path(address, self.block, self.interacted)
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport,
                                         follow_redirects=False) as c:
                r = await c.get(url, headers=_headers(self._api_key))
        except httpx.HTTPError as e:
            raise CheckUnavailable(f"could not reach the z402 check API: {type(e).__name__}") from e
        return _parse(r, self._api_key is not None)
