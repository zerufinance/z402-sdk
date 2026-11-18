# z402

Before an x402 agent pays a wallet, z402 asks zScreen: **PAY** or **DON'T PAY**.
DON'T PAY stops the payment before anything is signed. If the check cannot answer, the payment stops too.

z402 works on both sides of an x402 payment:

- **Buyer guard:** checks the seller's `payTo` wallet before your agent signs.
- **Seller guard:** checks the payer's wallet before your server verifies or settles.

SDKs for Python and TypeScript, Apache-2.0.

## Quick start

### 1. Install

```bash
pip install zeru-z402          # Python 3.10+, imports as `z402`
npm install zeru-z402          # Node 20+, ESM only
```

These are the `zeru-z402` packages. The packages named plain `z402` on PyPI and npm are unrelated projects.

No key is needed. Every IP address gets 1,000 free checks in total. They do not reset.

### 2. Guard your agent: one line

Python:

```python
import z402
z402.guard(client)          # client: your x402 x402Client or x402ClientSync
```

TypeScript:

```ts
import { guard } from "zeru-z402";
guard(client);              // client: your @x402/core x402Client (fetch or axios wrapper)
```

To block only some lists:

```python
z402.guard(client, block=["sanctioned", "scams"])
```

```ts
guard(client, { block: ["sanctioned", "scams"] });
```

A stopped payment is a `z402.Z402Blocked` (Python) or `Z402BlockedError` (TypeScript), with:

- `kind`: `dont_pay` or `check_unavailable`
- `reason`: one plain sentence
- `blocked_by` / `blockedBy`: the list that matched

The x402 HTTP wrappers re-throw hook errors as their own error. `z402.find_block(e)` / `findBlock(e)` finds the z402 block inside it.

### 3. Guard your server: the seller guard

Python:

```python
z402.seller_guard(server)   # server: your x402 x402ResourceServer
```

TypeScript:

```ts
import { sellerGuard } from "zeru-z402";
sellerGuard(server);        // server: your @x402/core x402ResourceServer
```

The seller guard checks the payer, the `from` of the payment authorization, before verify and before settle. A DON'T PAY payer is never verified and never settled.

### 4. Optional: a free key

A key is optional. A free key from https://zscreen.zeruai.org/app gives you a dashboard and a log of your checks. To use one, set `Z402_API_KEY`:

```bash
export Z402_API_KEY=<your key>
```

Limits: without a key, 1,000 checks in total for each IP address, never reset. With a key, 1,000 checks a month for each account. A burst guard also allows about 5 checks a second for each IP address, or for each key.

## The lists

| Name | What it holds |
|---|---|
| `sanctioned` | wallets on the US OFAC sanctions list |
| `tether_frozen` | wallets frozen by Tether |
| `circle_frozen` | wallets frozen by Circle |
| `hackers` | wallets tied to hacks and exploits |
| `scams` | scam wallets |
| `phishing` | phishing wallets |
| `ransomware` | ransomware wallets |
| `terror_financing` | wallets tied to terror financing |
| `mixers` | mixers |

The default is all of them (`z402.GROUPS` / `GROUPS`). An unknown list name is refused when the guard is set up.

`interacted` is on by default: a wallet that dealt directly with a listed wallet is blocked too. A contract, an exchange or a DEX is never blocked only because it dealt with a listed wallet. A wallet that is itself on a list is always blocked. Set `interacted=False` / `interacted: false` to block only the listed wallets themselves.

## Fail closed

z402 lets a payment through only on a well-formed `200` answer of `PAY`. Everything else stops it:

- the check API cannot be reached, or does not answer within the timeout (5 seconds by default)
- any other HTTP status, such as 400, 401, 403, 429 or 5xx
- a redirect (z402 never follows one)
- an answer that cannot be read

The limits count too: 1,000 checks in total for each IP address without a key (never reset), 1,000 a month for each account with a key, and a burst guard of about 5 checks a second. A check over a limit gets a `429`, and that payment stops. The decision detail gives the reason.

The reasoning: a guard that pays when it cannot check is not a guard. If you prefer to keep paying while the check is down, set `on_unavailable="warn"` / `onUnavailable: "warn"`. The payment then goes ahead and the miss is reported to your `on_warn` / `onWarn` callback. DON'T PAY always stops, whatever this setting says.

## Privacy and transport

- z402 sends only the wallet address being checked and the lists you chose. Nothing from your wallet, signer or private key is passed to it.
- Every check goes over HTTPS, with or without a key. A plain `http://` URL is refused at setup, except for `localhost`, `127.0.0.1` and `::1` (a local test server).
- With no key, no `X-API-Key` header is sent.

## Settings

| Python | TypeScript | Environment | Default |
|---|---|---|---|
| `api_key` | `apiKey` | `Z402_API_KEY` | none: no key needed |
| `base_url` | `baseUrl` | `Z402_API_URL` | `https://zscreen-api.zeruai.org` |
| `timeout` (seconds) | `timeoutMs` | | 5 s |
| `block` | `block` | | every list |
| `interacted` | `interacted` | | on |
| `on_unavailable` | `onUnavailable` | | `"stop"` |

## Plain API (no SDK)

```bash
curl "https://zscreen-api.zeruai.org/check/<wallet>?block=sanctioned,scams"                                # no key
curl -H "X-API-Key: $Z402_API_KEY" "https://zscreen-api.zeruai.org/check/<wallet>?block=sanctioned,scams"   # with a key
```

The answer:

```json
{"address": "0x...", "chain": "...", "verdict": "FLAGGED", "sentence": "...", "decision": "DONT_PAY", "blocked_by": "sanctioned"}
```

`verdict` is `FLAGGED` or `CLEAR`, and `decision` is `DONT_PAY` or `PAY`. `blocked_by` may be present on a `DONT_PAY`. Errors come back as `{"error": "<one sentence>"}` with status 400, 401, 403, 429 or 5xx. Add `interacted=false` to check the listed wallets only.

## How it hooks into x402

- **Buyer:** the x402 `on_before_payment_creation` / `onBeforePaymentCreation` hook. It runs after one `accepts` entry is picked and before the signer. If that entry is DON'T PAY the payment stops; z402 does not switch to another entry.
- **Seller:** `on_before_verify` and `on_before_settle` / `onBeforeVerify` and `onBeforeSettle`. The TypeScript seller hook returns an abort instead of throwing, because the x402 core ignores a hook that throws.

## Repository

- `python/`: the Python package (`zeru-z402` on PyPI). See [python/README.md](python/README.md).
- `typescript/`: the TypeScript package (`zeru-z402` on npm). See [typescript/README.md](typescript/README.md).
- `examples/`: example agents, and a Base Sepolia testnet demo.
- `demo/`: a demo against the live check API. Sellers are local and the wallet is new, so no money moves.
- `scripts/release_check.py`: builds the packages and checks what goes into them.

Tests run against local fakes only:

```bash
cd python && pip install -e ".[test]" && pytest
cd typescript && npm ci && npm run build && npm test
```

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE).
