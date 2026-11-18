// Example agent (TypeScript/Node, ESM): pay an x402 URL with z402 checking the payTo first.
//
//   export Z402_API_KEY=...                         # optional; free key: https://zscreen.zeruai.org/app
//   export AGENT_KEY_FILE=~/.config/agent/evm.key   # one line, 0x... private key
//   (cd typescript && npm install && npm run build) && (cd examples && npm install)   # or: npm install zeru-z402
//   node examples/ts_agent.mjs https://seller.example/paid
//
// The private key goes to the viem account only. The z402 check API sees the payTo address only.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { x402Client, wrapFetchWithPayment, decodePaymentResponseHeader } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { guard, findBlock } from "zeru-z402";

const url = process.argv[2];
const keyPath = process.env.AGENT_KEY_FILE.replace(/^~/, homedir());
const raw = readFileSync(keyPath, "utf8").trim();
const account = privateKeyToAccount(raw.startsWith("0x") ? raw : `0x${raw}`);

const client = new x402Client();
registerExactEvmScheme(client, { signer: account });
guard(client, {
  // block: ["sanctioned", "scams"],   // default: every list in GROUPS
  onDecision: (d) => console.log(`z402: ${d.kind} ${d.payTo} on ${d.network}: ${d.detail}`),
});

const fetchWithPay = wrapFetchWithPayment(fetch, client);
try {
  const r = await fetchWithPay(url);
  const pr = r.headers.get("PAYMENT-RESPONSE");
  console.log(`HTTP ${r.status}`, pr ? decodePaymentResponseHeader(pr) : "");
  console.log((await r.text()).slice(0, 500));
} catch (e) {
  const blk = findBlock(e);
  if (!blk) throw e;
  console.log(`NOT PAID (${blk.blockedBy ?? blk.kind}): ${blk.reason}`);
  process.exitCode = 2;
}
