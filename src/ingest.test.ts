import { describe, it, expect, vi } from "vitest";
import {
  handleIngest,
  MAX_BODY_BYTES,
  PAST_WINDOW_MS,
  FUTURE_SKEW_MS,
  KeyStoreUnavailableError,
  type IngestDeps,
  type IngestRequest,
} from "./ingest.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW_MS = 1_700_000_000_000;

const validEnvelope = {
  client_id: "win-3f2a",
  user_id: null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: "2023-11-14T22:13:20.000Z",
  events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }],
  sig: "hmac-sha256:abc",
};

function makeDeps(overrides: Partial<IngestDeps> = {}): IngestDeps {
  return {
    now: () => NOW_MS,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: () => true,
    verifyAppCheck: () => true,
    rateLimiter: { allow: () => true },
    replayCache: { checkAndRecord: () => true },
    deriveGeo: () => ({ country: "US", region: null }),
    bqInsert: vi.fn(),
    ...overrides,
  };
}

function req(body: unknown, extra: Partial<IngestRequest> = {}): IngestRequest {
  return { rawBody: JSON.stringify(body), ip: "203.0.113.7", ...extra };
}

describe("handleIngest — size cap (C2) & parse", () => {
  it("rejects an oversized body with 413 BEFORE parsing (raw bytes, not JSON)", async () => {
    const oversized = "x".repeat(MAX_BODY_BYTES + 1); // not even valid JSON
    const r = await handleIngest({ rawBody: oversized }, makeDeps());
    expect(r.status).toBe(413); // 413, not 400 → the cap ran before JSON.parse
  });

  it("rejects invalid JSON with 400", async () => {
    const r = await handleIngest({ rawBody: "{not json" }, makeDeps());
    expect(r.status).toBe(400);
  });

  it("rejects a non-object JSON body (array/scalar) with 400 before auth (EP1)", async () => {
    const verifyHmac = vi.fn(() => true);
    for (const raw of ["[]", "123", "null", '"x"']) {
      const r = await handleIngest({ rawBody: raw }, makeDeps({ verifyHmac }));
      expect(r.status, `body ${raw}`).toBe(400);
    }
    expect(verifyHmac).not.toHaveBeenCalled(); // EP1 precedes authenticity
  });
});

describe("handleIngest — authenticity (C5) fails closed", () => {
  it("401 when HMAC verification fails", async () => {
    const r = await handleIngest(req(validEnvelope), makeDeps({ verifyHmac: () => false }));
    expect(r.status).toBe(401);
  });

  it("401 when neither sig nor App Check token is present", async () => {
    const noSig = { ...validEnvelope, sig: undefined };
    const r = await handleIngest(req(noSig), makeDeps());
    expect(r.status).toBe(401);
  });

  it("uses App Check when a token is present, bypassing HMAC", async () => {
    const verifyHmac = vi.fn(() => false); // would 401 if consulted
    const r = await handleIngest(
      req(validEnvelope, { appCheckToken: "tok" }),
      makeDeps({ verifyHmac, verifyAppCheck: () => true }),
    );
    expect(r.status).toBe(202);
    expect(verifyHmac).not.toHaveBeenCalled();
  });

  it("401 when the App Check token is invalid", async () => {
    const r = await handleIngest(
      req(validEnvelope, { appCheckToken: "bad" }),
      makeDeps({ verifyAppCheck: () => false }),
    );
    expect(r.status).toBe(401);
  });

  // A1/F4 (SEC audit #2): the App-Check path now gets the SAME §5.4 freshness + replay nonce as HMAC.
  it("A1/F4: App-Check path records a token-keyed nonce (replay protection on both paths)", async () => {
    const checkAndRecord = vi.fn(() => true);
    const r = await handleIngest(
      req(validEnvelope, { appCheckToken: "tok-xyz" }),
      makeDeps({ verifyAppCheck: () => true, replayCache: { checkAndRecord } }),
    );
    expect(r.status).toBe(202);
    expect(checkAndRecord).toHaveBeenCalledWith("ac:tok-xyz", Date.parse(validEnvelope.sent_at) + PAST_WINDOW_MS);
  });
  it("A1/F4: a replayed App-Check envelope (nonce seen) → 401", async () => {
    const r = await handleIngest(
      req(validEnvelope, { appCheckToken: "tok" }),
      makeDeps({ verifyAppCheck: () => true, replayCache: { checkAndRecord: () => false } }),
    );
    expect(r.status).toBe(401);
  });
  it("A1/F4: stale/future sent_at on the App-Check path → 401; missing → 400 (fail closed)", async () => {
    const ac = { appCheckToken: "tok" };
    const stale = { ...validEnvelope, sent_at: new Date(NOW_MS - (PAST_WINDOW_MS + 60_000)).toISOString() };
    const future = { ...validEnvelope, sent_at: new Date(NOW_MS + (FUTURE_SKEW_MS + 60_000)).toISOString() };
    expect((await handleIngest(req(stale, ac), makeDeps({ verifyAppCheck: () => true }))).status).toBe(401);
    expect((await handleIngest(req(future, ac), makeDeps({ verifyAppCheck: () => true }))).status).toBe(401);
    expect((await handleIngest(req({ ...validEnvelope, sent_at: undefined }, ac), makeDeps({ verifyAppCheck: () => true }))).status).toBe(400);
  });
});

describe("handleIngest — KS-OUTAGE (transient key-store fault ≠ auth failure)", () => {
  it("503 (not 401) when verifyHmac throws a KeyStoreUnavailableError — retryable, no security event, no state touched", async () => {
    const onSecurityEvent = vi.fn();
    const rateLimiter = { allow: vi.fn(() => true) };
    const checkAndRecord = vi.fn(() => true);
    const bqInsert = vi.fn();
    const r = await handleIngest(
      req(validEnvelope),
      makeDeps({
        verifyHmac: () => { throw new KeyStoreUnavailableError(); },
        onSecurityEvent,
        rateLimiter,
        replayCache: { checkAndRecord },
        bqInsert,
      }),
    );
    expect(r.status).toBe(503); // retryable server fault, NOT a 401 auth rejection
    expect(r.body).toEqual({ error: "unavailable" });
    expect(onSecurityEvent).not.toHaveBeenCalled(); // an outage is not a client rejection — not logged as auth
    expect(rateLimiter.allow).not.toHaveBeenCalled(); // we threw before rate-limit…
    expect(checkAndRecord).not.toHaveBeenCalled(); // …and before the replay nonce — no state mutated
    expect(bqInsert).not.toHaveBeenCalled();
  });

  it("a bad/absent key (verifyHmac returns false) is still a 401 — the two are not conflated", async () => {
    const r = await handleIngest(req(validEnvelope), makeDeps({ verifyHmac: () => false }));
    expect(r.status).toBe(401);
  });

  it("an UNEXPECTED (non-KeyStore) throw from verifyHmac bubbles out (→ wrapper opaque 500), not a 503", async () => {
    await expect(
      handleIngest(req(validEnvelope), makeDeps({ verifyHmac: () => { throw new Error("boom"); } })),
    ).rejects.toThrow("boom");
  });
});

describe("handleIngest — replay nonce cache (SEC Q3 / D-STORE-CAS)", () => {
  it("401 when checkAndRecord reports the sig was already seen (replay)", async () => {
    const r = await handleIngest(req(validEnvelope), makeDeps({ replayCache: { checkAndRecord: () => false } }));
    expect(r.status).toBe(401);
  });

  it("atomically check-and-records on a fresh request, expiry anchored to sent_at + PAST_WINDOW", async () => {
    const checkAndRecord = vi.fn(() => true);
    const r = await handleIngest(req(validEnvelope), makeDeps({ replayCache: { checkAndRecord } }));
    expect(r.status).toBe(202);
    expect(checkAndRecord).toHaveBeenCalledWith("sig:hmac-sha256:abc", Date.parse(validEnvelope.sent_at) + PAST_WINDOW_MS);
  });
});

describe("handleIngest — replay freshness (§5.4, signed sent_at)", () => {
  const at = (deltaMs: number) => ({ ...validEnvelope, sent_at: new Date(NOW_MS - deltaMs).toISOString() });

  it("202 for an in-window sent_at (age 0)", async () => {
    expect((await handleIngest(req(at(0)), makeDeps())).status).toBe(202);
  });
  it("202 at the exact PAST_WINDOW edge", async () => {
    expect((await handleIngest(req(at(PAST_WINDOW_MS)), makeDeps())).status).toBe(202);
  });
  it("401 for a STALE sent_at (older than PAST_WINDOW)", async () => {
    expect((await handleIngest(req(at(PAST_WINDOW_MS + 1000)), makeDeps())).status).toBe(401);
  });
  it("401 for a FUTURE sent_at beyond FUTURE_SKEW (forgery/replay signal)", async () => {
    expect((await handleIngest(req(at(-(FUTURE_SKEW_MS + 1000))), makeDeps())).status).toBe(401);
  });
  it("202 within FUTURE_SKEW (small clock-ahead tolerated)", async () => {
    expect((await handleIngest(req(at(-FUTURE_SKEW_MS)), makeDeps())).status).toBe(202);
  });
  it("400 (not 401) when sent_at is MISSING — a malformed envelope, not a stale one", async () => {
    expect((await handleIngest(req({ ...validEnvelope, sent_at: undefined }), makeDeps())).status).toBe(400);
  });
  it("400 when sent_at is present but not ISO-8601", async () => {
    expect((await handleIngest(req({ ...validEnvelope, sent_at: "yesterday" }), makeDeps())).status).toBe(400);
  });
});

describe("handleIngest — pre-auth IP flood gate (SEC F2)", () => {
  it("a blocked IP → 429 BEFORE any parse/HMAC/nonce work", async () => {
    const verifyHmac = vi.fn(() => true);
    const checkAndRecord = vi.fn(() => true);
    const r = await handleIngest(
      req(validEnvelope),
      makeDeps({ ipRateGate: { allow: () => false }, verifyHmac, replayCache: { checkAndRecord } }),
    );
    expect(r.status).toBe(429);
    expect(verifyHmac).not.toHaveBeenCalled(); // shed before HMAC
    expect(checkAndRecord).not.toHaveBeenCalled(); // and before the nonce store
  });

  it("an allowed IP passes the gate through to 202", async () => {
    const r = await handleIngest(req(validEnvelope), makeDeps({ ipRateGate: { allow: () => true } }));
    expect(r.status).toBe(202);
  });
});

describe("handleIngest — PII-free security events (SEC F5)", () => {
  function assertPiiFree(e: object) {
    // 1) only the 3 declared fields — no PII field can ride along.
    expect(Object.keys(e).sort()).toEqual(["outcome", "reason", "status"]);
    // 2) none of the actual PII/secret VALUES from the fixtures appear anywhere.
    const json = JSON.stringify(e);
    for (const v of ["win-3f2a", "203.0.113.7", "hmac-sha256:abc"]) {
      expect(json, `security event leaked ${v}`).not.toContain(v);
    }
  }

  it("fires a coarse, PII-free event on each security rejection (413/429/401/replay)", async () => {
    const events: object[] = [];
    const deps = () => makeDeps({ onSecurityEvent: (e) => events.push(e) });

    // 413 size cap
    await handleIngest({ rawBody: "x".repeat(MAX_BODY_BYTES + 1), ip: "203.0.113.7" }, deps());
    // 429 IP flood
    await handleIngest(req(validEnvelope), makeDeps({ onSecurityEvent: (e) => events.push(e), ipRateGate: { allow: () => false } }));
    // 401 auth fail
    await handleIngest(req(validEnvelope), makeDeps({ onSecurityEvent: (e) => events.push(e), verifyHmac: () => false }));
    // 401 replay
    await handleIngest(req(validEnvelope), makeDeps({ onSecurityEvent: (e) => events.push(e), replayCache: { checkAndRecord: () => false } }));
    // 429 rate limited
    await handleIngest(req(validEnvelope), makeDeps({ onSecurityEvent: (e) => events.push(e), rateLimiter: { allow: () => false } }));

    const reasons = events.map((e) => (e as { reason: string }).reason);
    expect(reasons).toEqual(["size_cap", "ip_flood", "auth_failed", "replay", "rate_limited"]);
    for (const e of events) {
      expect((e as { outcome: string }).outcome).toBe("rejected");
      assertPiiFree(e);
    }
  });

  it("does NOT fire on a successful 202", async () => {
    const events: object[] = [];
    await handleIngest(req(validEnvelope), makeDeps({ onSecurityEvent: (e) => events.push(e) }));
    expect(events).toHaveLength(0);
  });
});

describe("handleIngest — rate limit (C3)", () => {
  it("429 when over limit", async () => {
    const r = await handleIngest(req(validEnvelope), makeDeps({ rateLimiter: { allow: () => false } }));
    expect(r.status).toBe(429);
  });

  it("passes client_id, IP, and the authenticated flag to the limiter", async () => {
    const allow = vi.fn(() => true);
    await handleIngest(req(validEnvelope), makeDeps({ rateLimiter: { allow } }));
    expect(allow).toHaveBeenCalledWith("win-3f2a", "203.0.113.7", true);
  });
});

describe("handleIngest — consent opacity (C4 + D1)", () => {
  it("202 and no write when consent is false", async () => {
    const bqInsert = vi.fn();
    const r = await handleIngest(req({ ...validEnvelope, consent: false }), makeDeps({ bqInsert }));
    expect(r.status).toBe(202);
    expect(bqInsert).not.toHaveBeenCalled();
  });

  it("202 (not 400) when consent is ABSENT — indistinguishable from consent:false", async () => {
    const r = await handleIngest(req({ ...validEnvelope, consent: undefined }), makeDeps());
    expect(r.status).toBe(202);
  });
});

describe("handleIngest — validation mapping", () => {
  it("400 for a malformed envelope (missing client_id) with consent granted", async () => {
    const r = await handleIngest(req({ ...validEnvelope, client_id: undefined }), makeDeps());
    expect(r.status).toBe(400);
  });

  it("413 for a batch over the cap", async () => {
    const events = Array.from({ length: 1001 }, () => ({ name: "app_open", ts: "2026-06-18T00:00:00Z" }));
    const r = await handleIngest(req({ ...validEnvelope, events }), makeDeps());
    expect(r.status).toBe(413);
  });

  it("202 (opaque) and no write when EVERY event is dropped by the allowlist", async () => {
    const bqInsert = vi.fn();
    const r = await handleIngest(
      req({ ...validEnvelope, events: [{ name: "spam_evt", ts: "2026-06-18T00:00:00Z" }] }),
      makeDeps({ bqInsert }),
    );
    expect(r.status).toBe(202); // not 400 — can't distinguish allowed from dropped
    expect(bqInsert).not.toHaveBeenCalled();
  });
});

describe("handleIngest — happy path, enrichment & EC2", () => {
  it("202 and writes GA4 rows with server timestamp + derived geo", async () => {
    const bqInsert = vi.fn();
    const r = await handleIngest(req(validEnvelope), makeDeps({ bqInsert }));
    expect(r.status).toBe(202);
    expect(r.body).toEqual({ ok: true });
    expect(bqInsert).toHaveBeenCalledTimes(1);
    const rows = bqInsert.mock.calls[0]![0];
    expect(rows).toHaveLength(1);
    expect(rows[0].event_timestamp).toBe(NOW_MS * 1000); // µs, server-stamped
    expect(rows[0].geo).toEqual({ country: "US", region: null });
    expect(rows[0].user_pseudo_id).toBe("win-3f2a");
  });

  it("EC2: writes ONLY accepted events — dropped ones never become rows", async () => {
    const bqInsert = vi.fn();
    await handleIngest(
      req({
        ...validEnvelope,
        events: [
          { name: "app_open", ts: "2026-06-18T00:00:00Z" },
          { name: "spam_evt", ts: "2026-06-18T00:00:00Z" }, // not allowlisted → dropped
          { name: "purchase", ts: "2026-06-18T00:00:01Z" },
        ],
      }),
      makeDeps({ bqInsert }),
    );
    const rows = bqInsert.mock.calls[0]![0];
    expect(rows.map((r: { event_name: string }) => r.event_name)).toEqual(["app_open", "purchase"]);
  });

  it("does not write when geo is null (no IP / suppressed) but still 202", async () => {
    const bqInsert = vi.fn();
    const r = await handleIngest(req(validEnvelope), makeDeps({ bqInsert, deriveGeo: () => null }));
    expect(r.status).toBe(202);
    expect(bqInsert.mock.calls[0]![0][0].geo).toBeNull();
  });
});
