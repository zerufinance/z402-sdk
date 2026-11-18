/**
 * z402: before an x402 agent pays a wallet, ask zScreen: PAY or DON'T PAY.
 *
 *   guard(client)                                   // buyer: every list blocked (default)
 *   guard(client, { block: ["sanctioned", "scams"] })
 *   sellerGuard(server)                             // seller: check the payer before verify/settle
 *
 * The check: GET {base}/check/<address>?block=a,b&interacted=false, with header X-API-Key
 * only when a key is set. The key is optional. The API allows 1,000 checks in total for each
 * IP address without a key (never reset), or 1,000 a month for each account with a key,
 * plus a burst guard of about 5 checks a second; it answers 429 over a limit.
 * Only the wallet address and the chosen lists are sent. Any answer other than a
 * well-formed 200 stops the payment (fail closed). Every check goes over HTTPS, with or
 * without a key; plain http is accepted for localhost, 127.0.0.1 and ::1 only.
 *
 * Buyer hook (@x402/core 2.28.0): `x402Client.onBeforePaymentCreation(hook)`. The core runs
 * it after one `accepts` entry is selected and before the scheme signer is called
 * (core/dist/esm/client/index.mjs:264-274). A hook that throws stops
 * `createPaymentPayload`, so no signature exists. `wrapFetchWithPayment` (@x402/fetch)
 * and `wrapAxiosWithPayment` (@x402/axios) both call `client.createPaymentPayload`.
 * Both wrappers re-throw hook errors as a plain Error and drop the original;
 * `findBlock(err)` recovers the Z402BlockedError from that.
 *
 * Seller hooks: `x402ResourceServer.onBeforeVerify` / `onBeforeSettle`. They must RETURN
 * `{abort: true, ...}`: the core only logs a hook that throws and carries on
 * (core/dist/esm/chunk-FV2JN4FK.mjs verifyPayment / settlePayment), so the seller hook
 * catches everything and aborts instead.
 */
import type { x402Client } from "@x402/core/client";
import type { x402ResourceServer } from "@x402/core/server";

export const CHECK_PATH = "/check/";
export const DEFAULT_BASE_URL = "https://zscreen-api.zeruai.org";
/** Where a free API key is made. */
export const KEY_URL = "https://zscreen.zeruai.org/app";
/** A clear verdict can take about 3 s, so the default leaves room for it. */
export const DEFAULT_TIMEOUT_MS = 5000;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
/** The lists a caller can block. Default: all of them. */
export const GROUPS = [
  "sanctioned", "tether_frozen", "circle_frozen", "hackers", "scams", "phishing",
  "ransomware", "terror_financing", "mixers",
] as const;
export type Group = (typeof GROUPS)[number];

export type Action = "stop" | "warn";
export type Kind = "pay" | "dont_pay" | "check_unavailable";

/** The 200 body of GET /check/<address>. */
export interface CheckResult {
  address: string;
  chain: string | null;
  verdict: "FLAGGED" | "CLEAR";
  sentence: string;
  decision: "DONT_PAY" | "PAY";
  blocked_by: string | null;
}

export interface Decision {
  action: "pay" | "stop" | "warn";
  kind: Kind;
  /** The wallet that was checked (payTo for the buyer, the payer for the seller). */
  payTo: string;
  network: string;
  result: CheckResult | null;
  detail: string;
}

export class CheckUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CheckUnavailableError";
  }
}

/**
 * No longer thrown: the API key is optional (no key = a keyless check).
 * Kept so code that imports or catches it keeps working.
 */
export class MissingApiKeyError extends Error {
  constructor() {
    super(`z402 needs an API key. Set Z402_API_KEY (or pass apiKey). Get a free key at ${KEY_URL}`);
    this.name = "MissingApiKeyError";
  }
}

/** The check API URL is not HTTPS (and not localhost). Thrown before any request is made. */
export class InsecureUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InsecureUrlError";
  }
}

/**
 * Return `url` without trailing slashes if a check may be sent to it, else throw InsecureUrlError.
 * https:// to any host is allowed; http:// only to localhost, 127.0.0.1 or [::1].
 */
export function requireSafeUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(String(url));
  } catch {
    throw new InsecureUrlError(`z402 check API URL is not a valid URL: ${JSON.stringify(url)}`);
  }
  const host = u.hostname.toLowerCase();
  if ((u.protocol === "https:" && host) || (u.protocol === "http:" && LOCAL_HOSTS.has(host))) {
    return String(url).replace(/\/+$/, "");
  }
  throw new InsecureUrlError(
    `z402 refuses to send the check to ${JSON.stringify(url)}: use an https:// URL ` +
      "(plain http is allowed only for localhost, 127.0.0.1 and ::1)",
  );
}

/** The key to send, or undefined (no key, empty or only spaces) for a keyless check. */
function optionalKey(apiKey: string | undefined): string | undefined {
  return typeof apiKey === "string" && apiKey.trim() ? apiKey : undefined;
}

export class Z402BlockedError extends Error {
  readonly decision: Decision;
  readonly kind: Kind;
  readonly verdict: "FLAGGED" | "CLEAR" | null;
  readonly reason: string;
  readonly blockedBy: string | null;
  readonly payTo: string;
  readonly network: string;

  constructor(d: Decision) {
    const label = d.kind === "dont_pay" ? "DON'T PAY" : d.kind.replace(/_/g, " ").toUpperCase();
    super(`z402 stopped the payment to ${d.payTo} on ${d.network}: ${label}: ${d.detail}`);
    this.name = "Z402BlockedError";
    this.decision = d;
    this.kind = d.kind;
    this.verdict = d.result?.verdict ?? null;
    this.reason = d.detail;
    this.blockedBy = d.result?.blocked_by ?? null;
    this.payTo = d.payTo;
    this.network = d.network;
  }
}

const DECISION_OF: Record<string, "DONT_PAY" | "PAY"> = { FLAGGED: "DONT_PAY", CLEAR: "PAY" };

/** undefined -> every list. Otherwise the names, checked. Unknown or empty -> throws. */
export function normalizeBlock(block?: readonly string[]): string[] | undefined {
  if (block === undefined || block === null) return undefined;
  if (typeof block === "string" || !Array.isArray(block)) {
    throw new TypeError('block must be a list of names, e.g. block: ["sanctioned", "scams"]');
  }
  const names = [...new Set(block.map((b) => String(b).trim().toLowerCase()))];
  if (names.length === 0) throw new RangeError(`block is empty: choose at least one of ${GROUPS.join(", ")}`);
  const bad = names.filter((n) => !(GROUPS as readonly string[]).includes(n));
  if (bad.length) throw new RangeError(`unknown block list ${bad.join(", ")}. Valid: ${GROUPS.join(", ")}`);
  return names;
}

export function checkPath(address: string, block: string[] | undefined, interacted: boolean): string {
  const q: string[] = [];
  if (block && !(block.length === GROUPS.length && GROUPS.every((g) => block.includes(g)))) {
    q.push("block=" + block.join(","));
  }
  if (!interacted) q.push("interacted=false");
  else q.push("hops=1", "contracts=1"); // direct contact only; a contract, exchange or DEX is never FLAGGED only for contact
  return CHECK_PATH + encodeURIComponent(address).replace(/%3A/gi, ":") + (q.length ? "?" + q.join("&") : "");
}

/** Validate a 200 body. Throws CheckUnavailableError on anything unusable. */
export function parseCheckResult(body: unknown): CheckResult {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new CheckUnavailableError("check API returned a non-object body");
  }
  const b = body as Record<string, unknown>;
  const verdict = b.verdict as string;
  if (!(verdict in DECISION_OF)) {
    throw new CheckUnavailableError(`check API returned an unknown verdict ${JSON.stringify(b.verdict)}`);
  }
  const decision = (b.decision ?? DECISION_OF[verdict]) as string;
  if (decision !== DECISION_OF[verdict]) {
    throw new CheckUnavailableError(`check API answer contradicts itself (${verdict} / ${JSON.stringify(decision)})`);
  }
  if (typeof b.sentence !== "string" || !b.sentence) {
    throw new CheckUnavailableError("check API returned no sentence");
  }
  return {
    address: String(b.address ?? ""),
    chain: (b.chain as string | null) ?? null,
    verdict: verdict as CheckResult["verdict"],
    sentence: b.sentence,
    decision: decision as CheckResult["decision"],
    blocked_by: (b.blocked_by as string | null) ?? null,
  };
}

/** Pure decision table. DONT_PAY always stops; onUnavailable applies only when there is no answer. */
export function decide(
  result: CheckResult | null,
  error: unknown,
  payTo: string,
  network: string,
  onUnavailable: Action = "stop",
): Decision {
  if (!result) {
    const msg = error instanceof Error ? error.message : String(error);
    return { action: onUnavailable, kind: "check_unavailable", payTo, network, result,
             detail: `the z402 check could not be completed (${msg})` };
  }
  if (result.decision === "DONT_PAY") {
    return { action: "stop", kind: "dont_pay", payTo, network, result, detail: result.sentence };
  }
  return { action: "pay", kind: "pay", payTo, network, result, detail: result.sentence };
}

export interface CheckOptions {
  /** Default: Z402_API_URL, then DEFAULT_BASE_URL. Must be https:// (http only for localhost). */
  baseUrl?: string;
  /** Default: Z402_API_KEY. Optional: with no key, no X-API-Key header is sent (a keyless check). */
  apiKey?: string;
  /** Default: DEFAULT_TIMEOUT_MS (5000). */
  timeoutMs?: number;
  /** Lists to block. Default: all of GROUPS. */
  block?: readonly string[];
  /** Also block wallets that dealt with a listed wallet directly. Default true. */
  interacted?: boolean;
  /** The fetch used to call the check API. Default: globalThis.fetch (never the payment-wrapped fetch). */
  fetch?: typeof globalThis.fetch;
}

/**
 * GET /check/<address>. Sends the address and the chosen lists. Nothing else.
 * Throws InsecureUrlError before any request; CheckUnavailableError for no usable answer.
 */
export async function checkWallet(address: string, opts: CheckOptions = {}): Promise<CheckResult> {
  const f = opts.fetch ?? globalThis.fetch;
  const env = envVars();
  const base = requireSafeUrl(opts.baseUrl ?? env.Z402_API_URL ?? DEFAULT_BASE_URL);
  const key = optionalKey(opts.apiKey ?? env.Z402_API_KEY);
  const headers: Record<string, string> = { Accept: "application/json" };
  if (key !== undefined) headers["X-API-Key"] = key; // no key: no header at all, not an empty one
  let r: Response;
  try {
    r = await f(base + checkPath(address, normalizeBlock(opts.block), opts.interacted ?? true), {
      method: "GET",
      headers,
      redirect: "error", // a redirect could carry the key elsewhere: never follow one
      signal: AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
  } catch (e) {
    throw new CheckUnavailableError(
      `could not reach the z402 check API: ${e instanceof Error ? e.name : "error"}`,
    );
  }
  let json: unknown;
  try {
    json = await r.json();
  } catch {
    throw new CheckUnavailableError(`check API answered HTTP ${r.status} with non-JSON`);
  }
  if (r.status !== 200) {
    const why = json && typeof json === "object" ? (json as { error?: unknown }).error : undefined;
    const hint = key !== undefined
      ? (r.status === 401 || r.status === 403 ? ` (check Z402_API_KEY; get a free key at ${KEY_URL})` : "")
      : (r.status === 401 || r.status === 403 || r.status === 429
          ? ` (no API key set; get a free key at ${KEY_URL} and set Z402_API_KEY)` : "");
    throw new CheckUnavailableError(`check API answered HTTP ${r.status}${why ? `: ${why}` : ""}${hint}`);
  }
  return parseCheckResult(json);
}

export interface GuardOptions extends CheckOptions {
  /** No answer from the check API: "stop" (default) or "warn" (pay and report). DONT_PAY always stops. */
  onUnavailable?: Action;
  onWarn?: (d: Decision) => void;
  onDecision?: (d: Decision) => void;
}

function envVars(): Record<string, string | undefined> {
  return (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env ?? {};
}

function resolve(opts: GuardOptions): CheckOptions & { onUnavailable: Action } {
  const env = envVars();
  // Every setting is checked now, when the guard is attached, not at payment time.
  return {
    baseUrl: requireSafeUrl(opts.baseUrl ?? env.Z402_API_URL ?? DEFAULT_BASE_URL),
    // "" = no key, so checkWallet does not fall back to Z402_API_KEY later, at payment time.
    apiKey: optionalKey(opts.apiKey ?? env.Z402_API_KEY) ?? "",
    timeoutMs: opts.timeoutMs,
    block: normalizeBlock(opts.block),
    interacted: opts.interacted ?? true,
    fetch: opts.fetch,
    onUnavailable: opts.onUnavailable ?? "stop",
  };
}

// Recent blocks by message, so findBlock() can recover them after the
// fetch/axios wrappers replace the error with a plain Error. Bounded.
const recentBlocks = new Map<string, Z402BlockedError>();
const RECENT_MAX = 256;

function remember(e: Z402BlockedError): void {
  recentBlocks.set(e.message, e);
  while (recentBlocks.size > RECENT_MAX) {
    const first = recentBlocks.keys().next().value;
    if (first === undefined) break;
    recentBlocks.delete(first);
  }
}

/** Return the Z402BlockedError behind `err` (direct, via `cause`, or wrapped by @x402/fetch / @x402/axios). */
export function findBlock(err: unknown): Z402BlockedError | null {
  const seen = new Set<unknown>();
  let e: unknown = err;
  while (e && !seen.has(e)) {
    if (e instanceof Z402BlockedError) return e;
    seen.add(e);
    if (e instanceof Error) {
      for (const [msg, blk] of recentBlocks) {
        if (e.message.endsWith(msg)) return blk;
      }
      e = (e as { cause?: unknown }).cause;
    } else break;
  }
  return null;
}

/** Buyer: register the check on an @x402/core x402Client. Returns the same client. */
export function guard<C extends Pick<x402Client, "onBeforePaymentCreation">>(
  client: C,
  opts: GuardOptions = {},
): C {
  const o = resolve(opts);
  client.onBeforePaymentCreation(async (ctx) => {
    const sel = ctx.selectedRequirements as unknown as Record<string, unknown>;
    const payTo = String(sel.payTo ?? "");
    const network = String(sel.network ?? "");
    let result: CheckResult | null = null;
    let error: unknown = null;
    try {
      result = await checkWallet(payTo, o);
    } catch (e) {
      error = e;
    }
    const d = decide(result, error, payTo, network, o.onUnavailable);
    opts.onDecision?.(d);
    if (d.action === "pay") return;
    if (d.action === "warn") {
      if (opts.onWarn) opts.onWarn(d);
      else console.warn(`z402: paying ${payTo} on ${network} although ${d.kind}: ${d.detail}`);
      return;
    }
    const blk = new Z402BlockedError(d);
    remember(blk);
    throw blk;
  });
  return client;
}

type Abort = { abort: true; reason: string; message?: string };

function payerOf(ctx: unknown): { payer: string; network: string; nonce: string } {
  const c = ctx as { paymentPayload?: { payload?: Record<string, unknown> }; requirements?: { network?: unknown } };
  const auth = c?.paymentPayload?.payload?.authorization as Record<string, unknown> | undefined;
  return {
    payer: typeof auth?.from === "string" ? auth.from : "",
    network: String(c?.requirements?.network ?? ""),
    nonce: typeof auth?.nonce === "string" ? auth.nonce : "",
  };
}

/**
 * Seller: check the PAYER (the EIP-3009 authorization `from`) before the facilitator is asked
 * to verify or settle. DONT_PAY or no answer -> verify/settle aborted, so the money never moves.
 * Returns the same server.
 */
export function sellerGuard<S extends Pick<x402ResourceServer, "onBeforeVerify" | "onBeforeSettle">>(
  server: S,
  opts: GuardOptions = {},
): S {
  const o = resolve(opts);
  const seen = new Map<string, Decision>();        // nonce -> decision, so settle reuses verify's

  const hook = async (ctx: unknown): Promise<void | Abort> => {
    try {
      const { payer, network, nonce } = payerOf(ctx);
      let d = nonce ? seen.get(nonce) : undefined;
      if (!d) {
        if (!payer) {
          d = { action: o.onUnavailable, kind: "check_unavailable", payTo: payer, network, result: null,
                detail: "the payer address could not be read from the payment" };
        } else {
          let result: CheckResult | null = null;
          let error: unknown = null;
          try {
            result = await checkWallet(payer, o);
          } catch (e) {
            error = e;
          }
          d = decide(result, error, payer, network, o.onUnavailable);
        }
        if (nonce) {
          seen.set(nonce, d);
          while (seen.size > RECENT_MAX) seen.delete(seen.keys().next().value as string);
        }
      }
      opts.onDecision?.(d);
      if (d.action === "pay") return;
      if (d.action === "warn") {
        if (opts.onWarn) opts.onWarn(d);
        else console.warn(`z402: accepting payer ${d.payTo} on ${d.network} although ${d.kind}: ${d.detail}`);
        return;
      }
      const by = d.result?.blocked_by;
      return { abort: true, reason: `z402: payer ${d.kind}${by ? ` (${by})` : ""}: ${d.detail}`,
               message: `Payment refused: ${d.detail}` };
    } catch (e) {
      // Never throw from a seller hook: the core would log it and carry on (fail open).
      return { abort: true, reason: `z402: payer check failed (${e instanceof Error ? e.message : String(e)})`,
               message: "Payment refused: the payer could not be checked." };
    }
  };
  server.onBeforeVerify(hook as Parameters<S["onBeforeVerify"]>[0]);
  server.onBeforeSettle(hook as Parameters<S["onBeforeSettle"]>[0]);
  return server;
}
