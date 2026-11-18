// z402 TypeScript guard + seller guard, end to end against local fakes and a fake z402 check API.
// Requirements:
//  R1 PAY -> payment proceeds; the check is GET {base}/check/<payTo> with X-API-Key; default = every list.
//  R2 DONT_PAY -> no signature; the error carries decision, sentence and the list that matched.
//  R3 block / interacted reach the API as ?block=a,b&interacted=false.
//  R4 an unknown or empty list choice is refused when the guard is set up.
//  R5 check API down / timeout / error / unreadable -> stop.
//  R6 the private key, the signature and the payer's own address never reach the check API.
//  R7 Z402_API_URL / Z402_API_KEY from the environment; the default URL is the public HTTPS API.
//  R8 the check (with or without a key) is never sent over plain http, except to localhost / 127.0.0.1 / ::1.
//  R9 no API key (none given, or empty) -> no error at setup; the check is sent with no X-API-Key
//     header at all. A refused keyless check (401/403/429) still stops and says where to get a free key.
//  R10 the default timeout (5 s) lets a slow clean verdict (about 3 s) through.
//  S  seller guard: the payer (authorization `from`) is checked before verify; DONT_PAY or no
//     answer -> never verified, never settled; PAY -> settled.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import axios from "axios";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { wrapAxiosWithPayment } from "@x402/axios";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import {
  encodePaymentRequiredHeader,
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { x402ResourceServer } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import {
  guard, sellerGuard, findBlock, checkWallet, Z402BlockedError, MissingApiKeyError, InsecureUrlError,
  GROUPS, DEFAULT_BASE_URL, DEFAULT_TIMEOUT_MS, KEY_URL,
} from "zeru-z402";

const NET = "eip155:84532";
const CLEAN = "0x9371cE1E5fDC59b5A3430D7f6B074daD1b834928";
const BAD = "0x1111111111111111111111111111111111111111";
const API_KEY = "test_key_not_a_real_key";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

// Every server is closed after each test, also when an assertion fails,
// so a failing test cannot hang the run.
const open = [];
afterEach(() => {
  for (const s of open.splice(0)) { s.closeAllConnections?.(); s.close(); }
});

function listen(handler) {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    open.push(s);
    s.listen(0, "127.0.0.1", () => resolve({ s, url: `http://127.0.0.1:${s.address().port}` }));
  });
}

async function fakeSeller(payTo) {
  const st = { signatures: [], requests: 0 };
  const { s, url } = await listen((req, res) => {
    st.requests++;
    const sig = req.headers["payment-signature"];
    if (!sig) {
      const pr = {
        x402Version: 2,
        error: "PAYMENT-SIGNATURE header is required",
        resource: { url: `${url}/paid`, description: "fake" },
        accepts: [{ scheme: "exact", network: NET, asset: USDC, amount: "10000", payTo,
                    maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } }],
      };
      res.writeHead(402, { "PAYMENT-REQUIRED": encodePaymentRequiredHeader(pr),
                           "Content-Type": "application/json" });
      return res.end("{}");
    }
    st.signatures.push(decodePaymentSignatureHeader(sig));
    const settle = { success: true, transaction: "0x" + "ab".repeat(32), network: NET,
                     payer: "0x" + "00".repeat(20) };
    res.writeHead(200, { "PAYMENT-RESPONSE": encodePaymentResponseHeader(settle),
                         "Content-Type": "application/json" });
    res.end(JSON.stringify({ data: "paid content" }));
  });
  return { ...st, st, s, url, close: () => s.close() };
}

// reply: an object (sent as JSON) or a string (sent as-is, e.g. an HTML error page).
async function fakeApi(reply, status = 200, delayMs = 0, extraHeaders = {}) {
  const captured = [];
  const { s, url } = await listen((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      captured.push({ method: req.method, path: req.url, headers: req.headers,
                      raw: Buffer.concat(chunks).toString() });
      setTimeout(() => {
        const raw = typeof reply === "string";
        res.writeHead(status, { "Content-Type": raw ? "text/html" : "application/json", ...extraHeaders });
        res.end(raw ? reply : JSON.stringify(reply));
      }, delayMs);
    });
  });
  return { captured, url, close: () => { s.closeAllConnections?.(); s.close(); } };
}

async function deadUrl() {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const port = s.address().port;
  await new Promise((r) => s.close(r));
  return `http://127.0.0.1:${port}`;
}

const answer = (address, decision, sentence, blockedBy = "sanctioned") => ({
  address, chain: "ethereum", verdict: decision === "DONT_PAY" ? "FLAGGED" : "CLEAR", sentence, decision,
  ...(decision === "DONT_PAY" ? { blocked_by: blockedBy } : {}),
});

const query = (c) => Object.fromEntries(new URL(c.path, "http://x").searchParams);
const pathOf = (c) => new URL(c.path, "http://x").pathname;

function makeClient(apiUrl, opts = {}) {
  const pk = generatePrivateKey();
  const account = privateKeyToAccount(pk);
  const spy = { calls: 0 };
  const signer = {
    address: account.address,
    signTypedData: async (m) => { spy.calls++; return account.signTypedData(m); },
  };
  const client = new x402Client();
  registerExactEvmScheme(client, { signer });
  guard(client, { baseUrl: apiUrl, apiKey: API_KEY, ...opts });
  return { client, spy, pk, account };
}

async function payWithFetch(client, url) {
  const f = wrapFetchWithPayment(fetch, client);
  try { return { r: await f(`${url}/paid`), err: null }; } catch (err) { return { r: null, err }; }
}

async function payWithAxios(client, url) {
  const ax = wrapAxiosWithPayment(axios.create(), client);
  try { return { r: await ax.get(`${url}/paid`), err: null }; } catch (err) { return { r: null, err }; }
}

const RUNNERS = [["fetch", payWithFetch], ["axios", payWithAxios]];

for (const [name, pay] of RUNNERS) {
  test(`${name}: PAY -> payment proceeds; GET /check/<payTo> with X-API-Key`, async () => {
    const api = await fakeApi(answer(CLEAN, "PAY", "This wallet is not on our lists."));
    const seller = await fakeSeller(CLEAN);
    const { client, spy } = makeClient(api.url);
    const { r, err } = await pay(client, seller.url);
    seller.close(); api.close();
    assert.equal(err, null, String(err));
    assert.equal(r.status, 200);
    assert.equal(spy.calls, 1);
    assert.equal(seller.st.signatures.length, 1);
    assert.equal(seller.st.signatures[0].payload.authorization.to.toLowerCase(), CLEAN.toLowerCase());
    assert.equal(api.captured.length, 1);
    assert.equal(api.captured[0].method, "GET");
    assert.equal(pathOf(api.captured[0]), `/check/${CLEAN}`);
    assert.deepEqual(query(api.captured[0]), { hops: "1", contracts: "1" }); // every list, direct contact only
    assert.equal(api.captured[0].headers["x-api-key"], API_KEY);
    assert.equal(api.captured[0].raw, "");
  });

  test(`${name}: DONT_PAY -> no signature, error carries sentence + list`, async () => {
    const sentence = "This wallet is on a list of phishing wallets.";
    const api = await fakeApi(answer(BAD, "DONT_PAY", sentence, "phishing"));
    const seller = await fakeSeller(BAD);
    const { client, spy } = makeClient(api.url);
    const { r, err } = await pay(client, seller.url);
    seller.close(); api.close();
    assert.equal(r, null);
    const blk = findBlock(err);
    assert.ok(blk instanceof Z402BlockedError, String(err));
    assert.equal(blk.kind, "dont_pay");
    assert.equal(blk.verdict, "FLAGGED");
    assert.equal(blk.reason, sentence);
    assert.equal(blk.blockedBy, "phishing");
    assert.equal(blk.payTo, BAD);
    assert.ok(String(err.message).includes(sentence));
    assert.ok(blk.message.includes("DON'T PAY"));
    assert.equal(spy.calls, 0);
    assert.equal(seller.st.signatures.length, 0);
    assert.equal(seller.st.requests, 1);
  });

  test(`${name}: block + interacted reach the API`, async () => {
    const api = await fakeApi(answer(CLEAN, "PAY", "Nothing found on the lists you chose to block."));
    const seller = await fakeSeller(CLEAN);
    const { client } = makeClient(api.url, { block: ["sanctioned", "scams"], interacted: false });
    const { err } = await pay(client, seller.url);
    seller.close(); api.close();
    assert.equal(err, null, String(err));
    assert.deepEqual(query(api.captured[0]), { block: "sanctioned,scams", interacted: "false" });
  });

  test(`${name}: contact counts only when the wallet dealt with a listed wallet itself`, async () => {
    const api = await fakeApi(answer(CLEAN, "PAY", "fine"));
    const seller = await fakeSeller(CLEAN);
    const { client } = makeClient(api.url);
    const { err } = await pay(client, seller.url);
    seller.close(); api.close();
    assert.equal(err, null, String(err));
    assert.equal(query(api.captured[0]).hops, "1");
  });

  test(`${name}: contracts, exchanges and DEXes are never flagged only for contact`, async () => {
    const api = await fakeApi(answer(CLEAN, "PAY", "fine"));
    const seller = await fakeSeller(CLEAN);
    const { client } = makeClient(api.url);
    const { err } = await pay(client, seller.url);
    seller.close(); api.close();
    assert.equal(err, null, String(err));
    assert.equal(query(api.captured[0]).contracts, "1");
  });

  test(`${name}: check API down -> stop`, async () => {
    const seller = await fakeSeller(CLEAN);
    const { client, spy } = makeClient(await deadUrl());
    const { r, err } = await pay(client, seller.url);
    seller.close();
    assert.equal(r, null);
    const blk = findBlock(err);
    assert.ok(blk, String(err));
    assert.equal(blk.kind, "check_unavailable");
    assert.equal(blk.verdict, null);
    assert.equal(spy.calls, 0);
    assert.equal(seller.st.signatures.length, 0);
  });

  test(`${name}: private key, signature and payer never sent to the check API`, async () => {
    const api = await fakeApi(answer(CLEAN, "PAY", "fine"));
    const seller = await fakeSeller(CLEAN);
    const { client, pk, account } = makeClient(api.url);
    const { err } = await pay(client, seller.url);
    seller.close(); api.close();
    assert.equal(err, null, String(err));
    const keyHex = pk.toLowerCase().replace(/^0x/, "");
    assert.equal(keyHex.length, 64);
    const sig = seller.st.signatures[0].payload.signature.toLowerCase().replace(/^0x/, "");
    assert.equal(api.captured.length, 1);
    for (const c of api.captured) {
      const blob = (c.path + c.raw + JSON.stringify(c.headers)).toLowerCase();
      assert.ok(!blob.includes(keyHex), "private key found in check request");
      assert.ok(!blob.includes(sig), "signature found in check request");
      assert.ok(!blob.includes(account.address.toLowerCase().slice(2)), "payer address sent");
      assert.equal(c.raw, "");
    }
  });
}

test("all lists chosen = the default", async () => {
  const api = await fakeApi(answer(CLEAN, "PAY", "fine"));
  const seller = await fakeSeller(CLEAN);
  const { client } = makeClient(api.url, { block: [...GROUPS] });
  await payWithFetch(client, seller.url);
  seller.close(); api.close();
  const q = query(api.captured[0]);
  assert.deepEqual(new Set((q.block ?? GROUPS.join(",")).split(",")), new Set(GROUPS));
  assert.ok(q.interacted === undefined || q.interacted === "true");
});

for (const bad of [["sanctioned", "nope"], [], "sanctioned"]) {
  test(`unknown or empty block ${JSON.stringify(bad)} is refused at setup`, () => {
    assert.throws(() => guard(new x402Client(), { block: bad, baseUrl: "http://127.0.0.1:9", apiKey: API_KEY }),
                  (e) => e instanceof RangeError || e instanceof TypeError);
  });
}

test("DONT_PAY cannot be relaxed by onUnavailable: warn", async () => {
  const api = await fakeApi(answer(BAD, "DONT_PAY", "Sanctioned.", "sanctioned"));
  const seller = await fakeSeller(BAD);
  const { client, spy } = makeClient(api.url, { onUnavailable: "warn" });
  const { err } = await payWithFetch(client, seller.url);
  seller.close(); api.close();
  assert.equal(findBlock(err)?.kind, "dont_pay");
  assert.equal(spy.calls, 0);
});

test("check down + onUnavailable: warn -> pays and reports", async () => {
  const seller = await fakeSeller(CLEAN);
  const seen = [];
  const { client, spy } = makeClient(await deadUrl(), { onUnavailable: "warn", onWarn: (d) => seen.push(d.kind) });
  const { r, err } = await payWithFetch(client, seller.url);
  seller.close();
  assert.equal(err, null, String(err));
  assert.equal(r.status, 200);
  assert.deepEqual(seen, ["check_unavailable"]);
  assert.equal(spy.calls, 1);
});

// The error answers the public API gives (status and body as the server sends them).
for (const [label, status, body, delay] of [
  ["HTTP 500", 500, { error: "Something went wrong." }, 0],
  ["HTTP 502", 502, { error: "The check is not available right now. Try again in a minute." }, 0],
  ["HTTP 401", 401, { error: "This API key is not valid. Create one in your developer dashboard." }, 0],
  ["HTTP 403", 403, { error: "This key cannot check." }, 0],
  ["HTTP 429 rate", 429, { error: "Too many checks: the Free plan allows 2 a second for each key." }, 0],
  ["HTTP 429 month", 429, { error: "You used all 100 verdicts on the free plan this month." }, 0],
  ["HTTP 400", 400, { error: "This is not a wallet address we recognise." }, 0],
  ["HTTP 400 list", 400, { error: "Unknown list: nope. Valid lists: sanctioned, scams." }, 0],
  ["HTML 404", 404, "<html>not found</html>", 0],
  ["HTML 502", 502, "<html>bad gateway</html>", 0],
  ["unknown verdict", 200, { verdict: "MAYBE", decision: "MAYBE", sentence: "x" }, 0],
  ["missing sentence", 200, { verdict: "CLEAR", decision: "PAY" }, 0],
  ["contradiction", 200, { verdict: "FLAGGED", decision: "PAY", sentence: "x" }, 0],
  ["timeout", 200, answer(CLEAN, "PAY", "fine"), 1000],
]) {
  test(`bad check reply (${label}) -> stop`, async () => {
    const api = await fakeApi(body, status, delay);
    const seller = await fakeSeller(CLEAN);
    const { client, spy } = makeClient(api.url, { timeoutMs: 200 });
    const { err } = await payWithFetch(client, seller.url);
    seller.close(); api.close();
    assert.equal(findBlock(err)?.kind, "check_unavailable", String(err));
    assert.equal(spy.calls, 0);
  });
}

test("Z402_API_URL / Z402_API_KEY from the environment; default URL", async () => {
  assert.equal(DEFAULT_BASE_URL, "https://zscreen-api.zeruai.org");
  const api = await fakeApi(answer(CLEAN, "PAY", "fine"));
  const seller = await fakeSeller(CLEAN);
  process.env.Z402_API_URL = api.url;
  process.env.Z402_API_KEY = "from_env_key";
  try {
    const account = privateKeyToAccount(generatePrivateKey());
    const client = new x402Client();
    registerExactEvmScheme(client, { signer: account });
    guard(client);
    const { r, err } = await payWithFetch(client, seller.url);
    assert.equal(err, null, String(err));
    assert.equal(r.status, 200);
    assert.equal(api.captured[0].headers["x-api-key"], "from_env_key");
  } finally {
    delete process.env.Z402_API_URL; delete process.env.Z402_API_KEY;
    seller.close(); api.close();
  }
});

test("checkWallet also reads Z402_API_URL / Z402_API_KEY from the environment", async () => {
  const api = await fakeApi(answer(CLEAN, "PAY", "fine"));
  process.env.Z402_API_URL = api.url;
  process.env.Z402_API_KEY = "from_env_key";
  try {
    const r = await checkWallet(CLEAN);
    assert.equal(r.decision, "PAY");
    assert.equal(api.captured.length, 1);
    assert.equal(api.captured[0].headers["x-api-key"], "from_env_key");
  } finally {
    delete process.env.Z402_API_URL; delete process.env.Z402_API_KEY;
    api.close();
  }
});

test("direct createPaymentPayload throws Z402BlockedError itself", async () => {
  const api = await fakeApi(answer(BAD, "DONT_PAY", "Sanctioned.", "sanctioned"));
  const { client, spy } = makeClient(api.url);
  const pr = { x402Version: 2, resource: { url: "http://x/paid" },
    accepts: [{ scheme: "exact", network: NET, asset: USDC, amount: "10000", payTo: BAD,
                maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } }] };
  await assert.rejects(client.createPaymentPayload(pr), (e) => e instanceof Z402BlockedError && e.kind === "dont_pay");
  api.close();
  assert.equal(spy.calls, 0);
});

// ------------------------------------------------------------------ seller guard
const SELLER = "0x" + "5e".repeat(20);
const REQ = { scheme: "exact", network: NET, asset: USDC, amount: "10000", payTo: SELLER,
              maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } };

function fakeFacilitator() {
  const st = { verified: 0, settled: 0 };
  return {
    st,
    async getSupported() { return { kinds: [{ x402Version: 2, scheme: "exact", network: NET }], extensions: [], signers: {} }; },
    async verify(p) { st.verified++; return { isValid: true, payer: p.payload.authorization.from }; },
    async settle(p) { st.settled++; return { success: true, transaction: "0x" + "cd".repeat(32), network: NET, payer: p.payload.authorization.from }; },
  };
}

async function signedPayload() {
  const account = privateKeyToAccount(generatePrivateKey());
  const c = new x402Client();
  registerExactEvmScheme(c, { signer: account });
  const payload = await c.createPaymentPayload({ x402Version: 2, resource: { url: "http://s/paid" }, accepts: [REQ] });
  return { payload, account };
}

async function sellerServer(apiUrl, opts = {}) {
  const fac = fakeFacilitator();
  const server = new x402ResourceServer(fac);
  server.register(NET, new ExactEvmScheme());
  await server.initialize();
  sellerGuard(server, { baseUrl: apiUrl, apiKey: "test_key", ...opts });
  return { server, fac };
}

async function verifyThenSettle(server, payload) {
  const v = await server.verifyPayment(payload, REQ);
  let settled = null, settleErr = null;
  try { settled = await server.settlePayment(payload, REQ); } catch (e) { settleErr = e; }
  return { v, settled, settleErr };
}

test("seller: DONT_PAY payer refused before verify and never settled; payer is what is checked", async () => {
  const { payload, account } = await signedPayload();
  const api = await fakeApi(answer(account.address, "DONT_PAY", "This wallet was frozen by Tether (USDT).", "tether_frozen"));
  const { server, fac } = await sellerServer(api.url);
  const { v, settled, settleErr } = await verifyThenSettle(server, payload);
  api.close();
  assert.equal(v.isValid, false);
  assert.ok(String(v.invalidReason).includes("tether_frozen"), v.invalidReason);
  assert.equal(settled, null);
  assert.ok(settleErr, "settle must be refused");
  assert.equal(fac.st.verified, 0);
  assert.equal(fac.st.settled, 0);
  assert.equal(pathOf(api.captured[0]), `/check/${account.address}`);
  assert.equal(api.captured[0].headers["x-api-key"], "test_key");
});

test("seller: PAY payer is verified and settled", async () => {
  const { payload, account } = await signedPayload();
  const api = await fakeApi(answer(account.address, "PAY", "Nothing found on the lists you chose to block."));
  const { server, fac } = await sellerServer(api.url, { block: ["sanctioned", "ransomware"], interacted: false });
  const { v, settled } = await verifyThenSettle(server, payload);
  api.close();
  assert.equal(v.isValid, true);
  assert.equal(settled?.success, true);
  assert.equal(fac.st.verified, 1);
  assert.equal(fac.st.settled, 1);
  assert.deepEqual(query(api.captured[0]), { block: "sanctioned,ransomware", interacted: "false" });
});

for (const [label, apiOpts] of [["down", null], ["HTTP 500", [{ error: "x" }, 500]], ["timeout", [{}, 200, 1000]]]) {
  test(`seller: check ${label} -> refused, never settled`, async () => {
    const { payload } = await signedPayload();
    const api = apiOpts ? await fakeApi(...apiOpts) : null;
    const { server, fac } = await sellerServer(api ? api.url : await deadUrl(), { timeoutMs: 200 });
    const { v, settleErr } = await verifyThenSettle(server, payload);
    api?.close();
    assert.equal(v.isValid, false);
    assert.ok(settleErr);
    assert.equal(fac.st.verified, 0);
    assert.equal(fac.st.settled, 0);
  });
}

test("seller: payment without a readable payer is refused (the hook never lets it through)", async () => {
  const { payload } = await signedPayload();
  const api = await fakeApi(answer(CLEAN, "PAY", "fine"));
  const { server, fac } = await sellerServer(api.url);
  const broken = { ...payload, payload: { signature: payload.payload.signature } };
  const { v } = await verifyThenSettle(server, broken);
  api.close();
  assert.equal(v.isValid, false);
  assert.equal(fac.st.verified, 0);
  assert.equal(fac.st.settled, 0);
});

test("seller: unknown list refused at setup", () => {
  assert.throws(() => sellerGuard(new x402ResourceServer(fakeFacilitator()), { block: ["hackers", "nope"], apiKey: "k" }),
                RangeError);
});

test("seller: signature never sent to the check API", async () => {
  const { payload, account } = await signedPayload();
  const api = await fakeApi(answer(account.address, "PAY", "fine"));
  const { server } = await sellerServer(api.url);
  await verifyThenSettle(server, payload);
  api.close();
  const sig = payload.payload.signature.toLowerCase().replace(/^0x/, "");
  assert.ok(api.captured.length >= 1);
  for (const c of api.captured) {
    assert.ok(!(c.path + c.raw + JSON.stringify(c.headers)).toLowerCase().includes(sig));
    assert.equal(c.raw, "");
  }
});

// ------------------------------------------------------------------ redirects and key hints
test("a redirect is never followed and stops the payment", async () => {
  const other = await fakeApi(answer(CLEAN, "PAY", "fine"));
  const api = await fakeApi({}, 302, 0, { Location: `${other.url}/check/${CLEAN}` });
  const seller = await fakeSeller(CLEAN);
  const { client, spy } = makeClient(api.url);
  const { err } = await payWithFetch(client, seller.url);
  seller.close(); api.close(); other.close();
  assert.equal(findBlock(err)?.kind, "check_unavailable", String(err));
  assert.equal(spy.calls, 0);
  assert.equal(api.captured.length, 1);
  assert.equal(other.captured.length, 0, "the key went to the redirect target");
});

for (const status of [401, 403]) {
  test(`HTTP ${status}: the error says where to get a key`, async () => {
    const api = await fakeApi({ error: "This API key is not valid." }, status);
    const seller = await fakeSeller(CLEAN);
    const { client } = makeClient(api.url);
    const { err } = await payWithFetch(client, seller.url);
    seller.close(); api.close();
    const blk = findBlock(err);
    assert.equal(blk?.kind, "check_unavailable");
    assert.ok(blk.reason.includes("Z402_API_KEY") && blk.reason.includes(KEY_URL), blk.reason);
  });
}

// ------------------------------------------------------------------ R7 default URL, no network
test("default URL is used when nothing is set (a stub fetch answers; nothing leaves the machine)", async () => {
  const seen = [];
  const stub = async (url, init) => {
    seen.push({ url, init });
    return new Response(JSON.stringify(answer(CLEAN, "PAY", "fine")), { status: 200 });
  };
  delete process.env.Z402_API_URL;
  const r = await checkWallet(CLEAN, { apiKey: API_KEY, fetch: stub });
  assert.equal(r.decision, "PAY");
  assert.ok(seen[0].url.startsWith(`https://zscreen-api.zeruai.org/check/${CLEAN}?`), seen[0].url);
  assert.equal(seen[0].init.headers["X-API-Key"], API_KEY);
  assert.equal(seen[0].init.redirect, "error");
});

// ------------------------------------------------------------------ R8 https only for the key
const INSECURE = ["http://zscreen-api.zeruai.org", "http://10.0.0.1:8090", "http://example.com",
  "http://127.0.0.1.example.com", "http://localhost@example.com", "http://localhost.example.com",
  "ftp://localhost", "zscreen-api.zeruai.org", "https://"];
const SAFE = ["http://localhost:8402", "http://127.0.0.1:8402", "http://[::1]:8402", "HTTP://LOCALHOST:1/",
  "https://zscreen-api.zeruai.org", "https://example.com:8443/base/"];

for (const url of INSECURE) {
  test(`insecure URL ${JSON.stringify(url)} is refused before any request`, async () => {
    let calls = 0;
    const stub = async () => { calls++; return new Response("{}"); };
    assert.throws(() => guard(new x402Client(), { apiKey: API_KEY, baseUrl: url }), InsecureUrlError);
    assert.throws(() => sellerGuard(new x402ResourceServer(fakeFacilitator()), { apiKey: API_KEY, baseUrl: url }),
                  InsecureUrlError);
    await assert.rejects(checkWallet(CLEAN, { apiKey: API_KEY, baseUrl: url, fetch: stub }), InsecureUrlError);
    assert.equal(calls, 0);
  });
}

for (const url of SAFE) {
  test(`https or localhost URL ${JSON.stringify(url)} is accepted`, () => {
    guard(new x402Client(), { apiKey: API_KEY, baseUrl: url });
  });
}

test("insecure Z402_API_URL from the environment is refused", () => {
  process.env.Z402_API_URL = "http://example.com";
  try {
    assert.throws(() => guard(new x402Client(), { apiKey: API_KEY }), InsecureUrlError);
    assert.throws(() => sellerGuard(new x402ResourceServer(fakeFacilitator()), { apiKey: API_KEY }), InsecureUrlError);
  } finally {
    delete process.env.Z402_API_URL;
  }
});

// ------------------------------------------------------------------ R9 no key
// [apiKey argument, Z402_API_KEY]: every way of having no key.
const NO_KEY = [[undefined, undefined], ["", undefined], ["   ", undefined], [undefined, ""], [undefined, "   "]];

async function withEnvKey(env, fn) {
  const saved = process.env.Z402_API_KEY;
  if (env === undefined) delete process.env.Z402_API_KEY; else process.env.Z402_API_KEY = env;
  try { return await fn(); } finally {
    if (saved === undefined) delete process.env.Z402_API_KEY; else process.env.Z402_API_KEY = saved;
  }
}

for (const [key, env] of NO_KEY) {
  test(`no key (apiKey ${JSON.stringify(key)}, Z402_API_KEY ${JSON.stringify(env)}): guard, sellerGuard and checkWallet send no X-API-Key header`, async () => {
    await withEnvKey(env, async () => {
      // buyer guard: no error at setup, the check is made without the header, the payment goes through
      const api = await fakeApi(answer(CLEAN, "PAY", "fine"));
      const seller = await fakeSeller(CLEAN);
      const { client, spy } = makeClient(api.url, { apiKey: key });
      const { r, err } = await payWithFetch(client, seller.url);
      seller.close();
      assert.equal(err, null, String(err));
      assert.equal(r.status, 200);
      assert.equal(spy.calls, 1);
      assert.equal(api.captured.length, 1);
      // seller guard: the payer is checked without the header, then verified and settled
      const { payload, account } = await signedPayload();
      const { server, fac } = await sellerServer(api.url, { apiKey: key });
      const { v, settled } = await verifyThenSettle(server, payload);
      assert.equal(v.isValid, true);
      assert.equal(settled?.success, true);
      assert.equal(fac.st.verified, 1);
      assert.equal(pathOf(api.captured[1]), `/check/${account.address}`);
      // checkWallet on its own
      const res = await checkWallet(CLEAN, { apiKey: key, baseUrl: api.url });
      assert.equal(res.decision, "PAY");
      api.close();
      assert.equal(api.captured.length, 3);
      for (const c of api.captured) assert.ok(!("x-api-key" in c.headers), JSON.stringify(c.headers));
    });
  });
}

test("no key: the old MissingApiKeyError class is still exported", () => {
  assert.equal(typeof MissingApiKeyError, "function");
  assert.ok(new MissingApiKeyError() instanceof Error);
});

for (const [status, body] of [
  [401, { error: "An API key is required." }],
  [403, { error: "This check is not allowed." }],
  [429, { error: "Too many checks at once. Slow down, or create a free key." }],
]) {
  test(`no key, HTTP ${status}: payment stops and the error says where to get a free key`, async () => {
    await withEnvKey(undefined, async () => {
      const api = await fakeApi(body, status);
      const seller = await fakeSeller(CLEAN);
      const { client, spy } = makeClient(api.url, { apiKey: undefined });
      const { err } = await payWithFetch(client, seller.url);
      seller.close(); api.close();
      const blk = findBlock(err);
      assert.equal(blk?.kind, "check_unavailable", String(err));
      assert.equal(spy.calls, 0);
      assert.equal(seller.st.signatures.length, 0);
      assert.ok(blk.reason.includes(KEY_URL) && blk.reason.includes("Z402_API_KEY"), blk.reason);
      assert.ok(blk.reason.includes(body.error), blk.reason);
    });
  });
}

for (const url of INSECURE) {
  test(`no key: insecure URL ${JSON.stringify(url)} is still refused before any request`, async () => {
    await withEnvKey(undefined, async () => {
      let calls = 0;
      const stub = async () => { calls++; return new Response("{}"); };
      assert.throws(() => guard(new x402Client(), { baseUrl: url }), InsecureUrlError);
      assert.throws(() => sellerGuard(new x402ResourceServer(fakeFacilitator()), { baseUrl: url }), InsecureUrlError);
      await assert.rejects(checkWallet(CLEAN, { baseUrl: url, fetch: stub }), InsecureUrlError);
      assert.equal(calls, 0);
    });
  });
}

// ------------------------------------------------------------------ R10 timeout
test("default timeout is 5 s", () => {
  assert.equal(DEFAULT_TIMEOUT_MS, 5000);
});

for (const [name, pay] of RUNNERS) {
  test(`${name}: a clear verdict that takes 2.5 s (over the old 2 s default) still pays`, async () => {
    const api = await fakeApi(answer(CLEAN, "PAY", "fine"), 200, 2500);
    const seller = await fakeSeller(CLEAN);
    const { client, spy } = makeClient(api.url);
    const { r, err } = await pay(client, seller.url);
    seller.close(); api.close();
    assert.equal(err, null, String(err));
    assert.equal(r.status, 200);
    assert.equal(spy.calls, 1);
  });
}
