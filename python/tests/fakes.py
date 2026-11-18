"""Local-only fakes: an x402 seller that answers 402, and the z402 check API.

Both are real HTTP servers on 127.0.0.1 with an OS-picked port, so the tests
exercise the real x402 httpx/requests transports and capture the exact bytes
each server received.
"""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from x402.http.utils import (
    decode_payment_signature_header,
    encode_payment_required_header,
    encode_payment_response_header,
)
from x402.schemas import PaymentRequired, PaymentRequirements, ResourceInfo, SettleResponse

USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


class _Server:
    def __init__(self, handler_cls: type[BaseHTTPRequestHandler]) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.httpd.owner = self  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


class FakeSeller(_Server):
    """GET /paid -> 402 with a v2 PAYMENT-REQUIRED header until a PAYMENT-SIGNATURE arrives."""

    def __init__(self, pay_to: str, network: str = "eip155:84532", amount: str = "10000") -> None:
        self.pay_to = pay_to
        self.network = network
        self.amount = amount
        self.signatures: list[dict[str, Any]] = []   # decoded PAYMENT-SIGNATURE payloads
        self.requests = 0
        seller = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def do_GET(self):
                seller.requests += 1
                sig = self.headers.get("PAYMENT-SIGNATURE")
                if not sig:
                    pr = PaymentRequired(
                        x402_version=2,
                        error="PAYMENT-SIGNATURE header is required",
                        resource=ResourceInfo(url=f"{seller.url}/paid", description="fake"),
                        accepts=[PaymentRequirements(
                            scheme="exact", network=seller.network, asset=USDC_BASE_SEPOLIA,
                            amount=seller.amount, pay_to=seller.pay_to, max_timeout_seconds=60,
                            extra={"name": "USDC", "version": "2"})],
                    )
                    self.send_response(402)
                    self.send_header("PAYMENT-REQUIRED", encode_payment_required_header(pr))
                    self.send_header("Content-Type", "application/json")
                    body = b"{}"
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                payload = decode_payment_signature_header(sig)
                seller.signatures.append(payload.model_dump(by_alias=True))
                settle = SettleResponse(success=True, transaction="0x" + "ab" * 32,
                                        network=seller.network, payer="0x" + "00" * 20)
                body = json.dumps({"data": "paid content"}).encode()
                self.send_response(200)
                self.send_header("PAYMENT-RESPONSE", encode_payment_response_header(settle))
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        super().__init__(H)


def answer(address: str, decision: str, sentence: str, blocked_by: str | None = None) -> dict[str, Any]:
    """A 200 body in the shape of the z402 check API (GET /check/<address>)."""
    body: dict[str, Any] = {"address": address, "chain": "ethereum",
                            "verdict": "FLAGGED" if decision == "DONT_PAY" else "CLEAR",
                            "sentence": sentence, "decision": decision}
    if decision == "DONT_PAY":
        body["blocked_by"] = blocked_by or "sanctioned"
    return body


class FakeCheckAPI(_Server):
    """GET /check/<address>. Returns ``self.reply`` with ``self.status`` and ``self.extra_headers``.

    ``self.raw_reply`` (bytes), when set, is sent as-is instead of JSON (an HTML error page,
    say). Every request is captured raw: method, path, headers, body bytes.
    """

    def __init__(self) -> None:
        self.reply: dict[str, Any] | None = None
        self.status = 200
        self.delay_s = 0.0
        self.raw_reply: bytes | None = None
        self.extra_headers: dict[str, str] = {}
        self.captured: list[dict[str, Any]] = []
        api = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                api.captured.append({"method": self.command, "path": self.path,
                                     "headers": dict(self.headers.items()), "raw": raw})
                if api.delay_s:
                    import time
                    time.sleep(api.delay_s)
                body = api.raw_reply if api.raw_reply is not None else json.dumps(api.reply).encode()
                self.send_response(api.status)
                self.send_header("Content-Type", "text/html" if api.raw_reply is not None
                                 else "application/json")
                for k, v in api.extra_headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _any
            do_POST = _any

        super().__init__(H)


def dead_url() -> str:
    """A 127.0.0.1 URL with nothing listening (port bound then released)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"
