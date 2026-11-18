# zeru-z402 (TypeScript)

Before an x402 agent pays a wallet, z402 asks zScreen: **PAY** or **DON'T PAY**.
DON'T PAY stops the payment before anything is signed. If the check cannot answer, the payment stops too.

**ESM only.** The package is an ES module and ships no CommonJS build. Use `import`, or `await import("zeru-z402")` from CommonJS code. Node 20 or later.

```bash
npm install zeru-z402 @x402/core
```

No key is needed. Each IP address gets 1,000 free checks in total (they do not reset), and a burst guard allows
about 5 checks a second. A free key from https://zscreen.zeruai.org/app is
optional: it gives you a dashboard and a log of your checks. To use one, set `Z402_API_KEY`:

```bash
export Z402_API_KEY=<your key>
```

## Buyer: check the seller before paying

```ts
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { guard, findBlock } from "zeru-z402";

const client = new x402Client();
registerExactEvmScheme(client, { signer: account });
guard(client);                                      // blocks every list (default)
// guard(client, { block: ["sanctioned", "scams"] }); // or only the lists you choose

const fetchWithPay = wrapFetchWithPayment(fetch, client);
try {
  await fetchWithPay(url);
} catch (e) {
  const blk = findBlock(e);    // the Z402BlockedError behind the wrapper's error, or null
  if (!blk) throw e;
  console.log(blk.kind, blk.blockedBy, blk.reason);
}
```

`guard` works with the `@x402/core` client, so it covers the `@x402/fetch` and `@x402/axios` wrappers.

A stopped payment is a `Z402BlockedError`:

- `.kind`: `dont_pay` or `check_unavailable`
- `.reason`: one plain sentence
- `.blockedBy`: the list that matched, such as `sanctioned`

## Seller: check the payer before settling

```ts
import { x402ResourceServer } from "@x402/core/server";
import { sellerGuard } from "zeru-z402";

const server = new x402ResourceServer(facilitatorClient);
sellerGuard(server);    // DON'T PAY payer: never verified, never settled
```

## Settings

| Option | Environment | Default |
|---|---|---|
| `apiKey` | `Z402_API_KEY` | none: no key needed |
| `baseUrl` | `Z402_API_URL` | `https://zscreen-api.zeruai.org` |
| `timeoutMs` | | 5000 |
| `block` | | every list in `GROUPS` |
| `interacted` | | `true`: also block wallets that dealt with a listed wallet directly |
| `onUnavailable` | | `"stop"`. `"warn"` pays when the check cannot answer, and reports it through `onWarn` |

Setup errors are thrown when the guard is attached, before any request:

- `InsecureUrlError` when the URL is not `https://`. Plain `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]`.
- `RangeError` for an unknown list name.

`MissingApiKeyError` is still exported, but it is no longer thrown: the key is optional.

## Fail closed

Only a well-formed `200` answer of `PAY` lets a payment through. Everything else stops it:

- a timeout or a network error
- any other HTTP status: 400, 401, 403, 429 or 5xx. A `429` means a limit was reached: 1,000 checks in total for each IP address without a key, 1,000 a month for each account with a key, or the burst guard of about 5 checks a second
- a redirect, which is never followed
- a body that cannot be read

`onUnavailable: "warn"` relaxes only these "no answer" cases. DON'T PAY always stops.

The check sends the wallet address and the lists you chose. Nothing from your wallet or signer is sent.

The full documentation is at https://github.com/zerufinance/z402-sdk.
