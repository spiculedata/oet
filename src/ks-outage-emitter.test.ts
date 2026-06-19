/**
 * QA — KS-OUTAGE end-to-end data-integrity (Spec §5; the payoff of the 3-state key store).
 *
 * DEV's tests prove the server side: a transient key-store fault → retryable 503 (not 401), bad/absent key
 * → 401. This suite closes the loop QA cares about — the REASON I held the condition: on a transient outage
 * the REAL emitter must **retain the data and recover**, not drop it. So:
 *   · key-store outage → server 503 → emitter KEEPS the buffer (no data loss); when the outage clears the
 *     same events flush successfully → exactly-once-ish delivery, nothing lost;
 *   · a genuinely bad/absent key → server 401 → emitter DROPS (won't succeed on resend) — proving the
 *     503-vs-401 distinction is what saves the data. (401-on-outage, the old behavior, would have dropped it.)
 *
 * Mocks only (in-process handler, swappable verify mode); no network/GCP.
 */
import { describe, it, expect, vi } from "vitest";
import {
  createEmitter,
  makeHmacSigner,
  createIngestHttpHandler,
  createInMemoryRateLimiter,
  createInMemoryReplayCache,
  makeBqInsert,
  KeyStoreUnavailableError,
  type EmitterConfig,
  type Ga4Row,
} from "./index.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;
const SECRET = "shared-app-secret";

type Mode = "outage" | "bad" | "ok";

/** In-process server with a swappable verify mode; collects written rows. */
function makeServer() {
  let mode: Mode = "ok";
  const written: Ga4Row[] = [];
  const handler = createIngestHttpHandler({
    now: () => NOW,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: async () => {
      if (mode === "outage") throw new KeyStoreUnavailableError(); // transient → core maps to 503
      return mode === "ok"; // "bad" → false → 401
    },
    rateLimiter: createInMemoryRateLimiter({ now: () => NOW }),
    replayCache: createInMemoryReplayCache(() => NOW),
    deriveGeo: () => null,
    bqInsert: makeBqInsert({ insertRows: async (rows) => { written.push(...rows); } }),
  });
  return { handler, written, setMode: (m: Mode) => { mode = m; } };
}

function emitterTo(handler: ReturnType<typeof makeServer>["handler"]): EmitterConfig {
  return {
    endpoint: "https://x/ingest",
    platform: "windows",
    appVersion: "2.2.0+27",
    consent: true,
    now: () => NOW,
    store: { load: () => null, save: () => {} },
    genId: () => "guid-1",
    sign: makeHmacSigner(SECRET),
    maxRetries: 1,
    transport: {
      post: vi.fn(async (_u: string, body: string, headers: Record<string, string>) => {
        const res = await handler({ headers, rawBody: body, ip: "203.0.113.7" });
        return { status: res.status };
      }),
    },
  };
}

describe("KS-OUTAGE end-to-end — outage retains data, recovers; bad key drops", () => {
  it("transient outage → 503 → emitter KEEPS the buffer (no data loss), then recovers when it clears", async () => {
    const srv = makeServer();
    srv.setMode("outage");
    const e = createEmitter(emitterTo(srv.handler));
    e.track("app_open");

    const r1 = await e.flush();
    expect(r1.ok).toBe(false); // server 503 (retryable) → flush didn't complete…
    expect(e.pending()).toBe(1); // …but the event is RETAINED — not dropped (the KS-OUTAGE win)
    expect(srv.written).toHaveLength(0);

    srv.setMode("ok"); // outage clears
    const r2 = await e.flush();
    expect(r2.ok).toBe(true);
    expect(e.pending()).toBe(0);
    expect(srv.written).toHaveLength(1); // the same event lands — nothing lost
  });

  it("bad/absent key → 401 → emitter DROPS (proves the 503-vs-401 distinction saves the data)", async () => {
    const srv = makeServer();
    srv.setMode("bad");
    const e = createEmitter(emitterTo(srv.handler));
    e.track("app_open");
    const r = await e.flush();
    expect(r.sent).toBe(0);
    expect(e.pending()).toBe(0); // 401 is non-retryable → dropped (an outage-as-401 would lose data here)
    expect(srv.written).toHaveLength(0);
  });
});
