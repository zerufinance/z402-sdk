# Base Sepolia demo (needs a funded testnet wallet)

Shows on a real testnet that a z402-guarded agent pays a normal seller and is
stopped before signing for a seller whose `payTo` is on a test list. The
result file records the transaction hash of the paid call.

## What you need

- Python 3.10+ with `x402[httpx,fastapi,evm]>=2.22,<3`, `uvicorn`, and z402
  (`pip install zeru-z402`, or `pip install -e ../../python` from this repo).
- Agent wallet: a Base Sepolia key with testnet USDC (Circle faucet,
  https://faucet.circle.com, Base Sepolia). One run spends about $0.001.
  The key file is one line, `chmod 600`. It is read by `run_demo.py` only.
- Two seller wallet addresses (they only receive): `SELLER_OK_PAYTO` and
  `SELLER_BAD_PAYTO`. They need no funds.

## Run

```bash
cd examples/base_sepolia_demo
echo "$SELLER_BAD_PAYTO" > test_list.txt

# 1. check API: the demo test-list stand-in (same answer shape as the z402 check API)
TEST_LIST_FILE=test_list.txt uvicorn test_list_check_api:app --port 8402 &

# 2. seller (settles via https://x402.org/facilitator on Base Sepolia)
SELLER_OK_PAYTO=0x... SELLER_BAD_PAYTO=0x... uvicorn seller:app --port 4021 &

# 3. agent
AGENT_KEY_FILE=~/.config/z402-demo/agent.key \
Z402_API_URL=http://127.0.0.1:8402 SELLER_URL=http://127.0.0.1:4021 \
python run_demo.py
```

Pass: exit 0, and `demo_result.json` has `ok.settle.success: true` with a
`tx_url` on sepolia.basescan.org, and `bad.stopped: true, verdict: FLAGGED`.
Check the tx on the explorer: the `to` of the USDC transfer is
`SELLER_OK_PAYTO`, and there is no transfer to `SELLER_BAD_PAYTO`.

## Notes

- `test_list_check_api.py` is a demo stand-in, not zScreen. It ignores the API
  key, so none is set here.
- Nothing here touches Base mainnet.

