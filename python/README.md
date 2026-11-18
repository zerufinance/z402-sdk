# zeru-z402 (Python)

Before an x402 agent pays a wallet, z402 asks zScreen: **PAY** or **DON'T PAY**.
DON'T PAY stops the payment before anything is signed. If the check cannot answer, the payment stops too.

```bash
pip install zeru-z402
```

No key is needed. Each IP address gets 1,000 free checks in total (they do not reset), and a burst guard allows
about 5 checks a second. A free key from https://zscreen.zeruai.org/app is
optional: it gives you a dashboard and a log of your checks. To use one, set `Z402_API_KEY`:

```bash
export Z402_API_KEY=<your key>
```

The package installs as `zeru-z402` and imports as `z402`.

## Buyer: check the seller before paying

```python
from x402 import x402Client
from x402.mechanisms.evm.exact import register_exact_evm_client
import z402

client = x402Client()                     # or x402ClientSync()
register_exact_evm_client(client, signer)
z402.guard(client)                                   # blocks every list (default)
# z402.guard(client, block=["sanctioned", "scams"])  # or only the lists you choose
```

One call covers every x402 transport that ends in `create_payment_payload` (httpx, requests, MCP).

A stopped payment raises `z402.Z402Blocked`, a subclass of x402's `PaymentAbortedError`:

- `.kind`: `dont_pay` or `check_unavailable`
- `.reason`: one plain sentence
- `.blocked_by`: the list that matched, such as `sanctioned`

The x402 HTTP wrappers re-raise hook errors as their own error. `z402.find_block(e)` finds the `Z402Blocked` inside it.

## Seller: check the payer before settling

```python
from x402 import x402ResourceServer
import z402

server = x402ResourceServer(facilitator_client)
z402.seller_guard(server)        # DON'T PAY payer: never verified, never settled
```

## Settings

| Argument | Environment | Default |
|---|---|---|
| `api_key` | `Z402_API_KEY` | none: no key needed |
| `base_url` | `Z402_API_URL` | `https://zscreen-api.zeruai.org` |
| `timeout` | | 5 seconds |
| `block` | | every list in `z402.GROUPS` |
| `interacted` | | `True`: also block wallets that dealt with a listed wallet directly |
| `on_unavailable` | | `"stop"`. `"warn"` pays when the check cannot answer, and reports it |

Setup errors are raised when the guard is attached, before any request:

- `z402.InsecureURL` when the URL is not `https://`. Plain `http://` is accepted only for `localhost`, `127.0.0.1` and `::1`.
- `ValueError` for an unknown list name.

`z402.MissingAPIKey` is still exported, but it is no longer raised: the key is optional.

## Fail closed

Only a well-formed `200` answer of `PAY` lets a payment through. Everything else stops it:

- a timeout or a network error
- any other HTTP status: 400, 401, 403, 429 or 5xx. A `429` means a limit was reached: 1,000 checks in total for each IP address without a key, 1,000 a month for each account with a key, or the burst guard of about 5 checks a second
- a redirect, which is never followed
- a body that cannot be read

`on_unavailable="warn"` relaxes only these "no answer" cases. DON'T PAY always stops.

The check sends the wallet address and the lists you chose. Nothing from your wallet or signer is sent.

## Tests

The tests run against local fakes only:

```bash
pip install -e ".[test]"
pytest
```

The full documentation is at https://github.com/zerufinance/z402-sdk.
