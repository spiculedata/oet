/**
 * QA M4 gate — emitter ↔ endpoint INTEGRATION round-trip (Spec §5–§8).
 *
 * DEV's emitter.test.ts proves each half in isolation: `validateEnvelope` accepts the built envelope,
 * and the server *would* recompute the same sig. This suite closes the loop QA owns — it pipes the
 * emitter's real, signed output through the real `createIngestHttpHandler` (HMAC verify → rate limit →
 * replay nonce → consent → validate → enrich → map → write) and asserts what actually lands:
 *   · a genuinely-signed flush is accepted and writes the right GA4 rows (emitter ↔ server agree
 *     byte-for-byte on the §5.2 canonical payload — the whole HMAC scheme works end-to-end, not in a mock);
 *   · tampering the body in transit, or signing with the wrong secret, is rejected 401 at the server;
 *   · a replayed (identical-sig) envelope is dedup'd by the server nonce → no double-write;
 *   · the App Check path (no sig, header token) round-trips through the HTTP wrapper.
 *
 * Nothing here touches a network or real GCP — the "server" is the in-process handler with injected
 * mocks. Real transport/endpoint/GCP wait for Owner GO.
 */
import { describe, it, expect, vi } from "vitest";
import {
  createEmitter,
  makeHmacSigner,
  createIngestHttpHandler,
  makeHmacVerifier,
  createInMemoryRateLimiter,
  createInMemoryReplayCache,
  makeBqInsert,
  type EmitterConfig,
  type ClientIdStore,
  type Ga4Row,
} from "./index.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;
const SECRET = "shared-app-secret";

function memStore(initial: string | null = null): ClientIdStore {
  let v = initial;
  return { load: () => v, save: (id) => { v = id; } };
}

/** An in-process "server": the real HTTP handler with injected mocks. Returns it + the rows it writes. */
function makeServer(opts: { secret?: string; appCheckToken?: string } = {}) {
  const written: Ga4Row[] = [];
  const handler = createIngestHttpHandler({
    now: () => NOW,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: makeHmacVerifier(() => opts.secret ?? SECRET),
    rateLimiter: createInMemoryRateLimiter({ now: () => NOW }),
    replayCache: createInMemoryReplayCache(() => NOW),
    deriveGeo: () => null,
    bqInsert: makeBqInsert({ insertRows: async (rows) => { written.push(...rows); } }),
    verifyAppCheckToken: async (t) => t === (opts.appCheckToken ?? "good-token"),
  });
  return { handler, written };
}

/** Emitter transport that pipes the POST straight into an in-process server handler. */
function pipeTo(handler: ReturnType<typeof makeServer>["handler"], mutate?: (body: string) => string) {
  return {
    post: vi.fn(async (_url: string, body: string, headers: Record<string, string>) => {
      const res = await handler({ headers, rawBody: mutate ? mutate(body) : body, ip: "203.0.113.7" });
      return { status: res.status };
    }),
  };
}

function config(over: Partial<EmitterConfig> = {}): EmitterConfig {
  return {
    endpoint: "https://ingest.example/ingest",
    platform: "windows",
    appVersion: "2.2.0+27",
    consent: true,
    transport: { post: vi.fn(async () => ({ status: 202 })) },
    now: () => NOW,
    store: memStore(),
    genId: () => "guid-1234",
    ...over,
  };
}

describe("M4 round-trip — a signed flush is accepted and writes the right rows", () => {
  it("emitter → endpoint → GA4 rows, end-to-end through the real HMAC/canonical path", async () => {
    const { handler, written } = makeServer();
    const e = createEmitter(config({ transport: pipeTo(handler), sign: makeHmacSigner(SECRET) }));
    e.track("app_open", { source: "win" });
    e.track("purchase");
    const r = await e.flush();

    expect(r).toEqual({ sent: 2, remaining: 0, ok: true }); // server accepted (202)
    expect(written.map((w) => w.event_name)).toEqual(["app_open", "purchase"]);
    expect(written[0]!.user_pseudo_id).toBe("windows-guid-1234"); // client_id → user_pseudo_id
    expect(written[0]!.event_timestamp).toBe(NOW * 1000); // server-stamped µs (not the client ts)
    expect(written[0]!.oet_ingest_version).toBe("oet.event.v1");
  });
});

describe("M4 round-trip — the signature actually protects the wire", () => {
  it("a body tampered in transit is rejected 401 (and the emitter drops it as non-retryable)", async () => {
    const { handler, written } = makeServer();
    // Flip an event name AFTER the emitter signed → server's recomputed HMAC won't match.
    const tamper = (body: string) => body.replace("app_open", "level_up");
    const e = createEmitter(config({ transport: pipeTo(handler, tamper), sign: makeHmacSigner(SECRET) }));
    e.track("app_open");
    const r = await e.flush();
    expect(r.sent).toBe(0);
    expect(written).toHaveLength(0); // nothing written — auth failed before validation
    expect(e.pending()).toBe(0); // 401 is non-retryable → dropped, not looped
  });

  it("an envelope signed with the WRONG secret is rejected 401", async () => {
    const { handler, written } = makeServer({ secret: SECRET });
    const e = createEmitter(config({ transport: pipeTo(handler), sign: makeHmacSigner("attacker-secret") }));
    e.track("app_open");
    const r = await e.flush();
    expect(r.sent).toBe(0);
    expect(written).toHaveLength(0);
  });
});

describe("M4 round-trip — replay nonce dedup across a re-send", () => {
  it("re-POSTing the identical signed envelope is dedup'd by the server (401), no double-write", async () => {
    const { handler, written } = makeServer();
    let captured = "";
    const capturing = {
      post: vi.fn(async (_u: string, body: string, headers: Record<string, string>) => {
        captured = body;
        const res = await handler({ headers, rawBody: body, ip: "1.2.3.4" });
        return { status: res.status };
      }),
    };
    const e = createEmitter(config({ transport: capturing, sign: makeHmacSigner(SECRET) }));
    e.track("app_open");
    await e.flush();
    expect(written).toHaveLength(1); // first send accepted + recorded in the nonce cache

    // The client retries the SAME bytes (e.g. a processed-but-timed-out send). Identical sig → replay.
    const replay = await handler({ headers: { "content-type": "application/json" }, rawBody: captured, ip: "1.2.3.4" });
    expect(replay.status).toBe(401); // nonce dedup
    expect(written).toHaveLength(1); // NOT double-counted
  });
});

describe("M4 round-trip — App Check path (no sig)", () => {
  it("an App-Check-token flush (no HMAC) round-trips to 202 + a written row", async () => {
    const { handler, written } = makeServer({ appCheckToken: "good-token" });
    const e = createEmitter(config({ transport: pipeTo(handler), appCheckToken: "good-token" })); // no sign
    e.track("app_open");
    const r = await e.flush();
    expect(r.ok).toBe(true);
    expect(written).toHaveLength(1);
  });

  it("a bad App-Check token is rejected 401", async () => {
    const { handler, written } = makeServer({ appCheckToken: "good-token" });
    const e = createEmitter(config({ transport: pipeTo(handler), appCheckToken: "forged" }));
    e.track("app_open");
    const r = await e.flush();
    expect(r.sent).toBe(0);
    expect(written).toHaveLength(0);
  });
});
