import { describe, it, expect, vi } from "vitest";
import { createHmac } from "node:crypto";
import { canonicalEnvelope } from "./canonical.js";
import {
  makeHmacVerifier,
  createInMemoryReplayCache,
  createInMemoryRateLimiter,
  createCoarseGeo,
  makeBqInsert,
  rowInsertId,
  createIngestHttpHandler,
  type AdapterDeps,
  type BqWriter,
} from "./ingest-adapter.js";
import type { Ga4Row } from "./ga4.js";
import { DEFAULT_ALLOWLIST } from "./index.js";
import { REPLAY_WINDOW_MS, MAX_BODY_BYTES } from "./ingest.js";

const SECRET = "test-secret-abc";
const baseEnv = {
  client_id: "win-3f2a",
  user_id: null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: "2023-11-14T22:13:20.000Z",
  events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }],
};
function sign(env: Record<string, unknown>, secret = SECRET) {
  const sig = "hmac-sha256:" + createHmac("sha256", secret).update(canonicalEnvelope(env)).digest("base64");
  return { ...env, sig };
}

describe("makeHmacVerifier — constant-time HMAC (AD2)", () => {
  const verify = makeHmacVerifier(() => SECRET);

  it("accepts a correctly signed envelope", () => {
    expect(verify(sign(baseEnv))).toBe(true);
  });
  it("verifies regardless of key order (canonicalization)", () => {
    const reordered = { events: baseEnv.events, consent: true, platform: "windows", app_version: "2.2.0+27", user_id: null, client_id: "win-3f2a" };
    expect(verify(sign(reordered))).toBe(true);
  });
  it("rejects a tampered body", () => {
    const signed = sign(baseEnv);
    expect(verify({ ...signed, client_id: "win-EVIL" })).toBe(false);
  });
  it("rejects a signature made with the wrong secret", () => {
    expect(verify(sign(baseEnv, "wrong-secret"))).toBe(false);
  });
  it("fails closed when sig is missing or the secret is unknown", () => {
    expect(verify(baseEnv)).toBe(false);
    expect(makeHmacVerifier(() => undefined)(sign(baseEnv))).toBe(false);
  });
});

describe("createInMemoryReplayCache (SEC Q3)", () => {
  it("checkAndRecord: true once (fresh), false on a repeat in the band, true again after expiry", () => {
    let t = 1000;
    const cache = createInMemoryReplayCache(() => t);
    expect(cache.checkAndRecord("sig-1", t + REPLAY_WINDOW_MS)).toBe(true); // fresh
    expect(cache.checkAndRecord("sig-1", t + REPLAY_WINDOW_MS)).toBe(false); // replay within the band
    t += REPLAY_WINDOW_MS + 1; // past the anchored expiry
    expect(cache.checkAndRecord("sig-1", t + REPLAY_WINDOW_MS)).toBe(true); // forgotten → fresh again
  });
});

describe("createInMemoryRateLimiter (C3 / AD4)", () => {
  it("enforces the per-client limit within a window", () => {
    let t = 0;
    const rl = createInMemoryRateLimiter({ now: () => t, perClient: 2, perIp: 100 });
    expect(rl.allow("c1", "ip1", true)).toBe(true);
    expect(rl.allow("c1", "ip1", true)).toBe(true);
    expect(rl.allow("c1", "ip1", true)).toBe(false); // 3rd in window → over
    t += 5 * 60 * 1000; // new window
    expect(rl.allow("c1", "ip1", true)).toBe(true);
  });
  it("enforces the per-IP limit across clients", () => {
    const rl = createInMemoryRateLimiter({ now: () => 0, perClient: 100, perIp: 2 });
    expect(rl.allow("c1", "shared", true)).toBe(true);
    expect(rl.allow("c2", "shared", true)).toBe(true);
    expect(rl.allow("c3", "shared", true)).toBe(false); // per-IP cap hit
  });
  it("on store outage: unauth fails CLOSED, auth fails OPEN under the global ceiling", () => {
    const rl = createInMemoryRateLimiter({ now: () => 0, globalCeiling: 2, storeAvailable: () => false });
    expect(rl.allow("c1", "ip1", false)).toBe(false); // unauth → closed
    expect(rl.allow("c1", "ip1", true)).toBe(true); // auth → open (1/2)
    expect(rl.allow("c1", "ip1", true)).toBe(true); // 2/2
    expect(rl.allow("c1", "ip1", true)).toBe(false); // ceiling still bounds auth
  });

  it("F-LIMITER-EVICT: the bucket map stays bounded under rotating client_id/IP (no memory-DoS)", () => {
    let t = 0;
    const W = 5 * 60 * 1000;
    const rl = createInMemoryRateLimiter({ now: () => t, windowMs: W });
    for (let i = 0; i < 1000; i++) rl.allow(`c${i}`, `ip${i}`, true); // rotating attacker
    expect(rl.bucketCount()).toBeGreaterThan(1000); // all distinct keys tracked in-window
    t += 2 * W; // both windows elapse — the old buckets are now dead
    rl.allow("trigger", "trigger", true); // any call triggers the sweep
    expect(rl.bucketCount()).toBeLessThan(50); // swept → map can't grow without bound
  });
});

describe("createCoarseGeo (EC1 / AD5)", () => {
  it("returns country only by default, region null", () => {
    const geo = createCoarseGeo({ lookupCountry: () => "US" });
    expect(geo("203.0.113.7")).toEqual({ country: "US", region: null });
  });
  it("includes region only when configured and above the suppression floor", () => {
    const geo = createCoarseGeo({
      lookupCountry: () => "US",
      lookupRegion: (ip) => (ip === "big" ? "CA" : "tiny"),
      regionSuppressed: (r) => r === "tiny",
    });
    expect(geo("big")).toEqual({ country: "US", region: "CA" });
    expect(geo("small")).toEqual({ country: "US", region: null }); // suppressed
  });
  it("returns null for no IP or unknown country (raw IP never echoed)", () => {
    const geo = createCoarseGeo({ lookupCountry: () => null });
    expect(geo(undefined)).toBeNull();
    expect(geo("1.2.3.4")).toBeNull();
  });
});

describe("makeBqInsert (AD6 bounded retry)", () => {
  it("succeeds on the first attempt", async () => {
    const writer: BqWriter = { insertRows: vi.fn(async () => {}) };
    await makeBqInsert(writer)([]);
    expect(writer.insertRows).toHaveBeenCalledTimes(1);
  });
  it("retries a transient failure then succeeds", async () => {
    let n = 0;
    const writer: BqWriter = { insertRows: vi.fn(async () => { if (n++ === 0) throw new Error("transient"); }) };
    await makeBqInsert(writer, { retries: 2 })([]);
    expect(writer.insertRows).toHaveBeenCalledTimes(2);
  });
  it("throws after exhausting retries", async () => {
    const writer: BqWriter = { insertRows: async () => { throw new Error("down"); } };
    await expect(makeBqInsert(writer, { retries: 1 })([])).rejects.toThrow("down");
  });

  it("F-WRITE-DEDUP: a retry resends IDENTICAL insertIds so BQ can dedup the double-write", async () => {
    const rows: Ga4Row[] = [
      { event_name: "app_open", event_timestamp: 1, event_params: [], user_pseudo_id: "u1", user_id: null, platform: "windows", app_info: { version: null }, geo: null, oet_ingest_version: "oet.event.v1" },
    ];
    const seen: (string[] | undefined)[] = [];
    let n = 0;
    const writer: BqWriter = {
      insertRows: vi.fn(async (_rows, insertIds) => { seen.push(insertIds); if (n++ === 0) throw new Error("partial"); }),
    };
    await makeBqInsert(writer, { retries: 2 })(rows);
    expect(seen).toHaveLength(2); // failed once, retried
    expect(seen[0]).toEqual(seen[1]); // same insertIds on the retry → dedup-safe
    expect(seen[0]).toEqual([rowInsertId(rows[0]!, 0)]);
  });

  it("F-WRITE-DEDUP: identical rows at different batch positions get DISTINCT ids (both kept)", () => {
    const row: Ga4Row = { event_name: "app_open", event_timestamp: 1, event_params: [], user_pseudo_id: "u1", user_id: null, platform: "windows", app_info: { version: null }, geo: null, oet_ingest_version: "oet.event.v1" };
    expect(rowInsertId(row, 0)).not.toBe(rowInsertId(row, 1)); // position-salted
    expect(rowInsertId(row, 0)).toBe(rowInsertId(row, 0)); // deterministic
  });
});

describe("createIngestHttpHandler — wrapper (AD1/AD3 + mapping)", () => {
  function deps(overrides: Partial<AdapterDeps> = {}): AdapterDeps {
    return {
      now: () => 1_700_000_000_000,
      allowlist: DEFAULT_ALLOWLIST,
      verifyHmac: makeHmacVerifier(() => SECRET),
      rateLimiter: { allow: () => true },
      replayCache: createInMemoryReplayCache(() => 1_700_000_000_000),
      deriveGeo: createCoarseGeo({ lookupCountry: () => "US" }),
      bqInsert: vi.fn(async () => {}),
      ...overrides,
    };
  }
  function http(body: unknown, extra: Partial<{ headers: Record<string, string | undefined>; ip: string }> = {}) {
    return { rawBody: typeof body === "string" ? body : JSON.stringify(body), headers: extra.headers ?? {}, ...(extra.ip ? { ip: extra.ip } : {}) };
  }

  it("AD1: rejects an oversized body with 413 at the transport, before the core", async () => {
    const handler = createIngestHttpHandler(deps());
    const res = await handler(http("x".repeat(MAX_BODY_BYTES + 1)));
    expect(res.status).toBe(413);
  });

  it("accepts a correctly HMAC-signed request → 202 with JSON body", async () => {
    const handler = createIngestHttpHandler(deps());
    const res = await handler(http(sign(baseEnv), { ip: "203.0.113.7" }));
    expect(res.status).toBe(202);
    expect(res.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(res.body)).toEqual({ ok: true });
  });

  it("AD3: App Check token is verified async and bypasses HMAC", async () => {
    const verifyHmac = vi.fn(() => false); // would 401 if consulted
    const verifyAppCheckToken = vi.fn(async () => true);
    const handler = createIngestHttpHandler(deps({ verifyHmac, verifyAppCheckToken }));
    const res = await handler(http(baseEnv, { headers: { "x-firebase-appcheck": "tok" }, ip: "203.0.113.7" }));
    expect(res.status).toBe(202);
    expect(verifyAppCheckToken).toHaveBeenCalledWith("tok");
    expect(verifyHmac).not.toHaveBeenCalled();
  });

  it("F10: a stray App-Check header is IGNORED when App Check is unconfigured (HMAC still runs → 202)", async () => {
    // deps() has no verifyAppCheckToken → App Check unconfigured. A stray header must not force the
    // App-Check path (which would 401); the valid HMAC signature must still win.
    const handler = createIngestHttpHandler(deps());
    const res = await handler(http(sign(baseEnv), { headers: { "x-firebase-appcheck": "stray-token" }, ip: "203.0.113.7" }));
    expect(res.status).toBe(202);
  });

  it("maps 429 with a Retry-After header", async () => {
    const handler = createIngestHttpHandler(deps({ rateLimiter: { allow: () => false } }));
    const res = await handler(http(sign(baseEnv), { ip: "203.0.113.7" }));
    expect(res.status).toBe(429);
    expect(res.headers["retry-after"]).toBe(String(REPLAY_WINDOW_MS / 1000));
  });

  it("a write failure surfaces as an opaque 500", async () => {
    const handler = createIngestHttpHandler(deps({ bqInsert: async () => { throw new Error("bq down"); } }));
    const res = await handler(http(sign(baseEnv), { ip: "203.0.113.7" }));
    expect(res.status).toBe(500);
    expect(JSON.parse(res.body)).toEqual({ error: "internal" }); // no detail leaked
  });

  it("a replayed (identical) signed request is rejected 401 the second time", async () => {
    const handler = createIngestHttpHandler(deps());
    const signed = sign(baseEnv);
    expect((await handler(http(signed, { ip: "203.0.113.7" }))).status).toBe(202);
    expect((await handler(http(signed, { ip: "203.0.113.7" }))).status).toBe(401); // nonce seen
  });
});
