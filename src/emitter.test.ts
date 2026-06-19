import { describe, it, expect, vi } from "vitest";
import { createHmac } from "node:crypto";
import {
  createEmitter,
  makeHmacSigner,
  type EmitterConfig,
  type ClientIdStore,
} from "./emitter.js";
import { canonicalEnvelope } from "./canonical.js";
import { validateEnvelope } from "./validate.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;

function memStore(initial: string | null = null): ClientIdStore {
  let v = initial;
  return { load: () => v, save: (id) => { v = id; } };
}

function okTransport() {
  return { post: vi.fn(async () => ({ status: 202 })) };
}

function config(overrides: Partial<EmitterConfig> = {}): EmitterConfig {
  return {
    endpoint: "https://ingest.example/ingest",
    platform: "windows",
    appVersion: "2.2.0+27",
    consent: true,
    transport: okTransport(),
    now: () => NOW,
    store: memStore(),
    genId: () => "guid-1234",
    ...overrides,
  };
}

describe("createEmitter — stable client_id (PII-free)", () => {
  it("mints a vendor-free <platform>-<guid> once and persists it", () => {
    const store = memStore();
    const e = createEmitter(config({ store }));
    expect(e.clientId).toBe("windows-guid-1234");
    expect(store.load()).toBe("windows-guid-1234");
  });
  it("reuses the persisted id on a later run (does not regenerate)", () => {
    const store = memStore("windows-existing");
    const genId = vi.fn(() => "should-not-be-used");
    const e = createEmitter(config({ store, genId }));
    expect(e.clientId).toBe("windows-existing");
    expect(genId).not.toHaveBeenCalled();
  });
});

describe("createEmitter — consent (LAW 2)", () => {
  it("collects and sends NOTHING without consent", async () => {
    const transport = okTransport();
    const e = createEmitter(config({ consent: false, transport }));
    e.track("app_open");
    expect(e.pending()).toBe(0);
    const r = await e.flush();
    expect(r).toEqual({ sent: 0, remaining: 0, ok: true });
    expect(transport.post).not.toHaveBeenCalled();
  });
});

describe("createEmitter — builds a spec-valid envelope (LAW 5)", () => {
  it("the flushed envelope is exactly what validateEnvelope accepts", async () => {
    const transport = okTransport();
    const e = createEmitter(config({ transport }));
    e.track("app_open", { source: "win" });
    e.track("purchase");
    await e.flush();
    const body = JSON.parse(transport.post.mock.calls[0]![1]);
    // The server's own validator must accept what the emitter produced.
    const result = validateEnvelope(body, DEFAULT_ALLOWLIST);
    expect(result.ok).toBe(true);
    expect(result.accepted).toHaveLength(2);
    expect(body.client_id).toBe("windows-guid-1234");
    expect(body.consent).toBe(true);
    expect(body.events[0].ts).toBe(new Date(NOW).toISOString());
  });
});

describe("createEmitter — HMAC sign ↔ server verify round-trip (§5.2)", () => {
  it("the emitted sig matches what the server recomputes from the canonical payload", async () => {
    const SECRET = "shared-app-secret";
    const transport = okTransport();
    const e = createEmitter(config({ transport, sign: makeHmacSigner(SECRET) }));
    e.track("app_open");
    await e.flush();
    const body = JSON.parse(transport.post.mock.calls[0]![1]);
    const expected = "hmac-sha256:" + createHmac("sha256", SECRET).update(canonicalEnvelope(body)).digest("base64");
    expect(body.sig).toBe(expected); // server would verify this with timingSafeEqual
  });
});

describe("createEmitter — flush, retry & buffering", () => {
  it("clears the buffer on a 202", async () => {
    const e = createEmitter(config());
    e.track("app_open");
    const r = await e.flush();
    expect(r).toEqual({ sent: 1, remaining: 0, ok: true });
    expect(e.pending()).toBe(0);
  });

  it("retries on transient (5xx/429/network) then succeeds", async () => {
    let n = 0;
    const post = vi.fn(async () => {
      n++;
      if (n === 1) throw new Error("network");
      if (n === 2) return { status: 503 };
      return { status: 202 };
    });
    const e = createEmitter(config({ transport: { post }, maxRetries: 3 }));
    e.track("app_open");
    const r = await e.flush();
    expect(r.ok).toBe(true);
    expect(post).toHaveBeenCalledTimes(3);
  });

  it("KEEPS the buffer when transient retries are exhausted (no data loss)", async () => {
    const post = vi.fn(async () => ({ status: 503 }));
    const e = createEmitter(config({ transport: { post }, maxRetries: 2 }));
    e.track("app_open");
    const r = await e.flush();
    expect(r.ok).toBe(false);
    expect(r.remaining).toBe(1);
    expect(e.pending()).toBe(1); // retained for the next flush
  });

  it("DROPS a chunk on a non-retryable 4xx (won't succeed on resend)", async () => {
    const post = vi.fn(async () => ({ status: 400 }));
    const e = createEmitter(config({ transport: { post } }));
    e.track("app_open");
    const r = await e.flush();
    expect(r.sent).toBe(0);
    expect(e.pending()).toBe(0); // dropped, not looped forever
    expect(post).toHaveBeenCalledTimes(1); // no retry on 4xx
  });

  it("splits a large buffer into ≤maxBatch envelopes", async () => {
    const transport = okTransport();
    const e = createEmitter(config({ transport, maxBatch: 1000 }));
    for (let i = 0; i < 2500; i++) e.track("app_open");
    const r = await e.flush();
    expect(r.sent).toBe(2500);
    expect(transport.post).toHaveBeenCalledTimes(3); // 1000 + 1000 + 500
  });
});
