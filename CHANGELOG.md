# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-11-18

### Fixed

- npm: the package's repository, homepage and issues links now point to
  https://github.com/zerufinance/z402-sdk. No code changes.

## [0.1.0] - 2026-11-18

First public release of `zeru-z402` for Python (PyPI) and TypeScript (npm).

### Added

- Buyer guard: `z402.guard(client)` / `guard(client)` asks the z402 check API about the
  seller's `payTo` wallet before the x402 payment is signed. DON'T PAY stops it.
- Seller guard: `z402.seller_guard(server)` / `sellerGuard(server)` checks the payer
  before verify and before settle.
- Nine lists to block: `sanctioned`, `tether_frozen`, `circle_frozen`, `hackers`, `scams`,
  `phishing`, `ransomware`, `terror_financing`, `mixers`. All are blocked by default.
- `interacted` (on by default) also blocks wallets that dealt directly with a listed wallet.
- Fail closed: anything other than a well-formed `200` answer stops the payment.
  `on_unavailable="warn"` / `onUnavailable: "warn"` pays and reports instead.
- Default API URL `https://zscreen-api.zeruai.org`, overridable with `Z402_API_URL`.
- The API key is optional. With no key, the check is sent with no `X-API-Key` header.
  Limits: without a key, 1,000 checks in total for each IP address, never reset; with a key,
  1,000 a month for each account; and a burst guard of about 5 checks a second. A free key
  from https://zscreen.zeruai.org/app, set as `Z402_API_KEY`, gives a dashboard and a log of your checks. A keyless check that is
  refused (401, 403 or 429) stops the payment and says where to get a free key.
- Every check goes over HTTPS, with or without a key (plain http only to localhost,
  127.0.0.1 and ::1), and redirects are never followed.
- Default timeout of 5 seconds, configurable (`timeout` / `timeoutMs`).
- Python: typed (`py.typed`). TypeScript: ESM only, Node 20 or later, type declarations included.

[0.1.1]: https://github.com/zerufinance/z402-sdk/releases/tag/v0.1.1
[0.1.0]: https://github.com/zerufinance/z402-sdk/releases/tag/v0.1.0
