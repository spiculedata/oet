/**
 * Ingestion endpoint ADAPTER (Spec §5–§8) — the real implementations of the injected `IngestDeps`
 * plus the HTTP wrapper, wiring the pure `handleIngest` core to a runtime.
 *
 * Split from the core on purpose: the core is pure control flow; this module holds the crypto, the
 * stores, and the I/O seams. The pieces that would touch real GCP — the BigQuery client, the geo
 * provider, App Check via the Firebase Admin SDK, Secret Manager — are themselves INJECTED here
 * (`BqWriter`, `lookupCountry`, `verifyAppCheckToken`, `SecretLookup`), with mock/in-memory defaults
 * for tests. So this whole module runs against the emulator / mocks; a real GCP project, BigQuery
 * dataset, or deploy waits for the **Owner's GO** (authority map). Nothing here reaches a live
 * service on its own.
 *
 * Addresses the QA/SEC adapter findings: AD1 transport byte-cap, AD2 timingSafeEqual + secret
 * hygiene, AD3 App-Check async pre-verify, AD4 limiter global ceiling + fail-open/closed, AD5
 * country-only geo, AD6 write-retry. Residual F-RETRY/SP1 (nonce keyed on sig, no signed request
 * ts) is documented, not papered over — it needs the v0.1.1 signed `sent_at`.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalEnvelope, canonicalize } from "./canonical.js";
import {
  handleIngest,
  MAX_BODY_BYTES,
  REPLAY_WINDOW_MS,
  type IngestDeps,
  type IngestRequest,
  type IpRateGate,
  type RateLimiter,
  type ReplayCache,
} from "./ingest.js";
import type { Ga4Geo, Ga4Row } from "./ga4.js";

// ── AD2: HMAC verification (constant-time) ───────────────────────────────────
/** Resolve the per-app HMAC secret for a request (real: Secret Manager; tests: a fixture map). */
export type SecretLookup = (body: Record<string, unknown>) => string | undefined;

/**
 * Build the core's `verifyHmac`: recompute `hmac-sha256:<base64(HMAC(secret, canonicalEnvelope))>`
 * and compare to `body.sig` in **constant time**. Fails closed on a missing/short secret or any
 * length mismatch. The secret never leaves this closure and is never logged (AD2 / DOMAIN LAW 7).
 */
export function makeHmacVerifier(getSecret: SecretLookup): IngestDeps["verifyHmac"] {
  return (body) => {
    const sig = body.sig;
    if (typeof sig !== "string") return false;
    const secret = getSecret(body);
    if (!secret) return false; // no key → no trust (fail closed)
    const expected =
      "hmac-sha256:" +
      createHmac("sha256", secret).update(canonicalEnvelope(body)).digest("base64");
    const got = Buffer.from(sig, "utf8");
    const want = Buffer.from(expected, "utf8");
    if (got.length !== want.length) return false; // unequal length ⇒ not equal (and timingSafeEqual would throw)
    try {
      return timingSafeEqual(got, want);
    } catch {
      return false;
    }
  };
}

// ── replay nonce cache (SEC Q3) ──────────────────────────────────────────────
/**
 * In-memory sig nonce cache, single-instance only. `checkAndRecord` is atomic by virtue of JS's
 * single-threaded run-to-completion: the get + set happen with no `await` between them, so two
 * concurrent calls can't interleave. (Cross-instance correctness needs the shared store; D-STORE.)
 */
export function createInMemoryReplayCache(now: () => number): ReplayCache {
  const expiry = new Map<string, number>();
  return {
    checkAndRecord(sig, expiresAtMs) {
      const t = now();
      // opportunistic eviction so the map can't grow unbounded
      for (const [k, exp] of expiry) if (exp <= t) expiry.delete(k);
      const exp = expiry.get(sig);
      if (exp !== undefined && exp > t) return false; // already present in the fresh band → replay
      expiry.set(sig, expiresAtMs);
      return true; // newly recorded
    },
  };
}

// ── C3 / AD4: rate limiter ───────────────────────────────────────────────────
export interface RateLimitOptions {
  now: () => number;
  windowMs?: number; // default 5 min
  perClient?: number; // default 60 / window
  perIp?: number; // default 600 / window
  globalCeiling?: number; // default 6000 / window — caps even authenticated traffic (AD4)
  /** Backing-store health. When it returns false, the SEC fail-open/closed policy kicks in. */
  storeAvailable?: () => boolean;
}

/**
 * Fixed-window limiter, per client_id AND per IP, under a global ceiling. SEC §5.4 policy: on a
 * backing-store outage, **unauthenticated traffic fails closed** (deny) while **authenticated
 * traffic fails open but only under the global ceiling** (AD4) — an outage can't be ridden into
 * unbounded cost.
 */
export function createInMemoryRateLimiter(
  opts: RateLimitOptions,
): RateLimiter & { bucketCount(): number } {
  const windowMs = opts.windowMs ?? 5 * 60 * 1000;
  const perClient = opts.perClient ?? 60;
  const perIp = opts.perIp ?? 600;
  const ceiling = opts.globalCeiling ?? 6000;
  const buckets = new Map<string, { count: number; start: number }>();
  let lastSweep = opts.now();

  // F-LIMITER-EVICT: a fixed-window bucket is dead once its window has elapsed (the next access
  // resets it anyway), so it can be dropped. Without this, every distinct client_id/IP persists
  // forever — and client_id is forgeable under App Check, so a rotating attacker grows the map
  // without bound = memory-DoS (the anti-flood control becomes the amplifier, DOMAIN LAW 4). Sweep
  // at most once per window (amortized cheap) so the map can't retain buckets older than ~2 windows.
  function maybeSweep(t: number): void {
    if (t - lastSweep < windowMs) return;
    lastSweep = t;
    for (const [k, b] of buckets) if (t - b.start >= windowMs) buckets.delete(k);
  }

  function underLimit(key: string, limit: number, t: number): boolean {
    let b = buckets.get(key);
    if (!b || t - b.start >= windowMs) {
      b = { count: 0, start: t };
      buckets.set(key, b);
    }
    b.count++;
    return b.count <= limit;
  }

  return {
    allow(clientId, ip, authenticated) {
      const t = opts.now();
      maybeSweep(t);
      if (opts.storeAvailable && !opts.storeAvailable()) {
        if (!authenticated) return false; // fail CLOSED for unauth
        return underLimit("global", ceiling, t); // fail OPEN for auth, but under the ceiling
      }
      const okGlobal = underLimit("global", ceiling, t);
      const okClient = underLimit(`c:${clientId}`, perClient, t);
      const okIp = underLimit(`ip:${ip ?? "?"}`, perIp, t);
      return okGlobal && okClient && okIp;
    },
    /** Live count of tracked buckets — for tests/metrics to assert the map stays bounded. */
    bucketCount() {
      return buckets.size;
    },
  };
}

// ── F2: cheap pre-auth per-IP flood gate (no I/O, in-memory) ─────────────────
/**
 * A per-IP fixed-window gate, in-memory and sync — the cheap first line that runs before parse/HMAC/
 * nonce. Self-evicts dead buckets (≤1×/window) so a rotating-IP flood can't grow the map unbounded
 * (same memory-DoS guard as the main limiter). Defaults: 300 requests / 1 min per IP.
 */
export function createInMemoryIpRateGate(opts: {
  now: () => number;
  windowMs?: number;
  perIp?: number;
}): IpRateGate {
  const windowMs = opts.windowMs ?? 60 * 1000;
  const perIp = opts.perIp ?? 300;
  const buckets = new Map<string, { count: number; start: number }>();
  let lastSweep = opts.now();
  return {
    allow(ip) {
      const t = opts.now();
      if (t - lastSweep >= windowMs) {
        lastSweep = t;
        for (const [k, b] of buckets) if (t - b.start >= windowMs) buckets.delete(k);
      }
      const key = ip ?? "?";
      let b = buckets.get(key);
      if (!b || t - b.start >= windowMs) {
        b = { count: 0, start: t };
        buckets.set(key, b);
      }
      b.count++;
      return b.count <= perIp;
    },
  };
}

// ── EC1 / AD5: coarse geo ────────────────────────────────────────────────────
export interface GeoOptions {
  /** IP → ISO country code, or null if unknown. Real: a geo DB/service (Owner GO). */
  lookupCountry: (ip: string) => string | null;
  /** Optional region lookup; region stays OFF unless a deployment supplies this (AD5 / ruling #4). */
  lookupRegion?: (ip: string) => string | null;
  /** k-anonymity floor: return true to suppress a too-small region (→ region null). */
  regionSuppressed?: (region: string) => boolean;
}

/** Country-only by default; region only when configured AND above the suppression floor. Raw IP never returned. */
export function createCoarseGeo(opts: GeoOptions): IngestDeps["deriveGeo"] {
  return (ip) => {
    if (!ip) return null;
    const country = opts.lookupCountry(ip);
    if (country === null) return null;
    let region: string | null = null;
    if (opts.lookupRegion) {
      const r = opts.lookupRegion(ip);
      if (r !== null && !(opts.regionSuppressed?.(r) ?? false)) region = r;
    }
    const geo: Ga4Geo = { country, region };
    return geo;
  };
}

// ── AD6: BigQuery write with bounded retry + idempotent insertId ─────────────
export interface BqWriter {
  /**
   * Insert rows. `insertIds[i]` is a stable best-effort dedup key for `rows[i]` — pass it through to
   * BigQuery's streaming `insertId` so a retried insert (same ids) is de-duplicated server-side.
   */
  insertRows(rows: Ga4Row[], insertIds?: string[]): Promise<void>;
}

/**
 * Stable per-row dedup key (F-WRITE-DEDUP). A partial-write-then-throw makes `makeBqInsert` resend
 * the SAME rows; without an `insertId` BigQuery streaming would double-write them = duplicate-event
 * metric poisoning (DOMAIN LAW 3/4). We key on the canonical row content PLUS its batch index, so a
 * retry reproduces identical ids (→ BQ dedups) while two legitimately-identical events in one batch
 * (same content, same ctx timestamp) keep DISTINCT ids and are both kept.
 */
export function rowInsertId(row: Ga4Row, index: number): string {
  return createHmac("sha256", "oet-insert-id")
    .update(`${index}:${canonicalize(row)}`)
    .digest("hex");
}

/**
 * Wrap a BQ writer with bounded retry so a TRANSIENT failure doesn't bubble to a 5xx that the
 * client then retries — which the replay nonce would reject, losing the data (AD6). Retries send the
 * SAME deterministic `insertId`s (F-WRITE-DEDUP) so a partial write can't double-count. The residual
 * (a hard failure after the nonce is recorded) is the F-RETRY/SP1 gap: without a signed request
 * timestamp, a legit retry is indistinguishable from a replay. Tracked for spec v0.1.1.
 */
export function makeBqInsert(
  writer: BqWriter,
  opts: { retries?: number } = {},
): IngestDeps["bqInsert"] {
  const retries = opts.retries ?? 2;
  return async (rows) => {
    const insertIds = rows.map((r, i) => rowInsertId(r, i)); // computed once → stable across retries
    let lastErr: unknown;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        await writer.insertRows(rows, insertIds);
        return;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr;
  };
}

// ── HTTP wrapper ─────────────────────────────────────────────────────────────
export interface RawHttpRequest {
  headers: Record<string, string | undefined>;
  /** Raw, unparsed body. */
  rawBody: string;
  ip?: string;
}

export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** Adapter deps = the core deps minus the sync `verifyAppCheck`, plus an async-capable token verifier. */
export interface AdapterDeps extends Omit<IngestDeps, "verifyAppCheck"> {
  /** Verify a Firebase App Check token (real: Admin SDK, async). Absent ⇒ App Check disabled. */
  verifyAppCheckToken?: (token: string) => boolean | Promise<boolean>;
  /** Header name carrying the App Check token (default `x-firebase-appcheck`). */
  appCheckHeader?: string;
}

function jsonResult(status: number, body: unknown, extra: Record<string, string> = {}): HttpResult {
  return { status, headers: { "content-type": "application/json", ...extra }, body: JSON.stringify(body) };
}

/**
 * Build the HTTP handler. It enforces the **transport byte cap before anything else** (AD1 —
 * defense-in-depth on top of the core's C2; a real platform should also cap upstream), does the
 * **async App Check pre-verify** and injects the boolean result into the (sync) core (AD3), then
 * maps the core `IngestResponse` to HTTP (adding `Retry-After` on 429). Opaque bodies throughout (§6).
 */
export function createIngestHttpHandler(deps: AdapterDeps) {
  const appCheckHeader = deps.appCheckHeader ?? "x-firebase-appcheck";
  return async (httpReq: RawHttpRequest): Promise<HttpResult> => {
    // AD1: cap at the transport before building the core request.
    if (Buffer.byteLength(httpReq.rawBody, "utf8") > MAX_BODY_BYTES) {
      return jsonResult(413, { error: "payload_too_large" });
    }

    // F10: only treat the App Check header as a token when App Check is CONFIGURED. Otherwise a stray
    // `x-firebase-appcheck` header would force the (unverifiable) App-Check path → 401, blocking a
    // perfectly valid HMAC request. Unconfigured ⇒ ignore the header entirely and let HMAC run.
    const token = deps.verifyAppCheckToken ? httpReq.headers[appCheckHeader] : undefined;
    let appCheckResult = false;
    if (token !== undefined && deps.verifyAppCheckToken) {
      appCheckResult = await deps.verifyAppCheckToken(token);
    }

    const coreDeps: IngestDeps = {
      now: deps.now,
      allowlist: deps.allowlist,
      verifyHmac: deps.verifyHmac,
      verifyAppCheck: () => appCheckResult, // async pre-verified, injected sync (AD3)
      rateLimiter: deps.rateLimiter,
      replayCache: deps.replayCache,
      deriveGeo: deps.deriveGeo,
      bqInsert: deps.bqInsert,
    };

    const req: IngestRequest = {
      rawBody: httpReq.rawBody,
      ...(httpReq.ip !== undefined ? { ip: httpReq.ip } : {}),
      ...(token !== undefined ? { appCheckToken: token } : {}),
    };

    let res;
    try {
      res = await handleIngest(req, coreDeps);
    } catch {
      // A write failure (after retries) or unexpected error → opaque 500; never leak detail (§6).
      return jsonResult(500, { error: "internal" });
    }
    const extra = res.status === 429 ? { "retry-after": String(Math.ceil(REPLAY_WINDOW_MS / 1000)) } : {};
    return jsonResult(res.status, res.body, extra);
  };
}
