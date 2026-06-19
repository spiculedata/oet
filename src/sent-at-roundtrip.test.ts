/**
 * QA — emitter↔endpoint `sent_at` freshness round-trip (Spec v0.1.1 §5.4/§5.5; gate Q1', end-to-end).
 *
 * DEV's ingest.test.ts proves the freshness window with hand-built envelopes fed to handleIngest. This
 * suite closes the loop QA owns: the REAL reference emitter stamps `sent_at` itself, so this proves that
 * stamped value flows through the real `createIngestHttpHandler` and is freshness-checked — i.e. a client
 * whose clock is badly skewed is rejected at the server (§5.4 "clock skew" is intended), while a synced
 * client is accepted. Mocks only; no network/GCP.
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
  type Ga4Row,
} from "./index.js";
import { DEFAULT_ALLOWLIST } from "./index.js";
// NOTE [F-EXPORTS, QA finding]: PAST_WINDOW_MS / FUTURE_SKEW_MS are NOT re-exported from index.ts
// (it still re-exports only the deprecated REPLAY_WINDOW_MS alias), so they're imported from ./ingest.js
// here. Recommend index.ts re-export the two new canonical window constants. Non-blocking.
import { PAST_WINDOW_MS, FUTURE_SKEW_MS } from "./ingest.js";

const SERVER_NOW = 1_700_000_000_000;
const SECRET = "shared-app-secret";

/** In-process server: real HTTP handler with a fixed clock, injected mocks. */
function makeServer() {
  const written: Ga4Row[] = [];
  const handler = createIngestHttpHandler({
    now: () => SERVER_NOW,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: makeHmacVerifier(() => SECRET),
    rateLimiter: createInMemoryRateLimiter({ now: () => SERVER_NOW }),
    replayCache: createInMemoryReplayCache(() => SERVER_NOW),
    deriveGeo: () => null,
    bqInsert: makeBqInsert({ insertRows: async (rows) => { written.push(...rows); } }),
  });
  return { handler, written };
}

/** An emitter whose clock is `skewMs` ahead of (or, negative, behind) the server, piping to `handler`. */
function emitterAt(skewMs: number, handler: ReturnType<typeof makeServer>["handler"]): EmitterConfig {
  return {
    endpoint: "https://x/ingest",
    platform: "windows",
    appVersion: "2.2.0+27",
    consent: true,
    now: () => SERVER_NOW + skewMs, // emitter stamps sent_at from ITS clock
    store: { load: () => null, save: () => {} },
    genId: () => "guid-1",
    sign: makeHmacSigner(SECRET),
    transport: {
      post: vi.fn(async (_u: string, body: string, headers: Record<string, string>) => {
        const res = await handler({ headers, rawBody: body, ip: "203.0.113.7" });
        return { status: res.status };
      }),
    },
  };
}

describe("Q1' end-to-end — emitter sent_at ↔ server freshness", () => {
  it("a synced emitter (clock = server) flushes → 202 and writes", async () => {
    const { handler, written } = makeServer();
    const e = createEmitter(emitterAt(0, handler));
    e.track("app_open");
    const r = await e.flush();
    expect(r.ok).toBe(true);
    expect(written).toHaveLength(1);
  });

  it("an emitter clock LAGGING beyond PAST_WINDOW is rejected 401 (stale sent_at), nothing written", async () => {
    const { handler, written } = makeServer();
    const e = createEmitter(emitterAt(-(PAST_WINDOW_MS + 60_000), handler)); // 6 min behind
    e.track("app_open");
    const r = await e.flush();
    expect(r.sent).toBe(0);
    expect(written).toHaveLength(0); // freshness rejected the real emitter's stamped sent_at
  });

  it("an emitter clock AHEAD beyond FUTURE_SKEW is rejected 401 (future sent_at)", async () => {
    const { handler, written } = makeServer();
    const e = createEmitter(emitterAt(FUTURE_SKEW_MS + 60_000, handler)); // 2 min ahead
    e.track("app_open");
    const r = await e.flush();
    expect(r.sent).toBe(0);
    expect(written).toHaveLength(0);
  });

  it("a transport retry reuses the SAME sent_at — the freshness anchor doesn't shift mid-retry", async () => {
    const { handler } = makeServer();
    // First send 503 (transient) then accept: the emitter rebuilds nothing, re-sends identical bytes.
    let n = 0;
    const cfg = emitterAt(0, handler);
    cfg.transport = {
      post: vi.fn(async (_u: string, body: string, headers: Record<string, string>) => {
        n++;
        if (n === 1) return { status: 503 }; // transient → emitter retries the SAME body
        const res = await handler({ headers, rawBody: body, ip: "203.0.113.7" });
        return { status: res.status };
      }),
    };
    const e = createEmitter(cfg);
    e.track("app_open");
    const r = await e.flush();
    expect(r.ok).toBe(true); // retry with the same sent_at is still fresh → accepted
  });
});
