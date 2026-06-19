/**
 * QA — SEC F3 user_id PII guard at the ENDPOINT level (full-stack, the acceptance's stated level).
 *
 * DEV's validate.test.ts asserts `validateEnvelope` emits `invalid_user_id`. F3's acceptance is "→ 400",
 * which is an ENDPOINT outcome: it only holds if `invalid_user_id` is in `handleIngest`'s
 * ENVELOPE_400_REASONS (else it would fall through to the opaque all-dropped 202). This pins that
 * cross-layer wiring end-to-end so a future edit can't silently demote an email-laden user_id to 202.
 */
import { describe, it, expect, vi } from "vitest";
import { handleIngest, type IngestDeps, type IngestRequest } from "./ingest.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;
const base = {
  client_id: "win-1",
  user_id: null as string | null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: new Date(NOW).toISOString(),
  events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }],
  sig: "hmac-sha256:x",
};
function deps(over: Partial<IngestDeps> = {}): IngestDeps {
  return {
    now: () => NOW,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: () => true, // auth precedes validate; isolate the user_id rule
    verifyAppCheck: () => true,
    rateLimiter: { allow: () => true },
    replayCache: { checkAndRecord: () => true },
    deriveGeo: () => null,
    bqInsert: vi.fn(),
    ...over,
  };
}
const req = (body: unknown): IngestRequest => ({ rawBody: JSON.stringify(body), ip: "203.0.113.7" });

describe("F3 — user_id PII guard, end-to-end through handleIngest", () => {
  it("an email-shaped user_id → 400 (NOT opaque 202), nothing written", async () => {
    const bqInsert = vi.fn();
    const r = await handleIngest(req({ ...base, user_id: "alice@example.com" }), deps({ bqInsert }));
    expect(r.status).toBe(400); // invalid_user_id ∈ ENVELOPE_400_REASONS → 400, not the all-dropped 202
    expect(bqInsert).not.toHaveBeenCalled(); // PII never reaches the warehouse (DOMAIN LAW 1)
  });

  it("a user_id over 128 chars → 400", async () => {
    const r = await handleIngest(req({ ...base, user_id: "u".repeat(129) }), deps());
    expect(r.status).toBe(400);
  });

  it("a valid opaque user_id → 202 + written; null (anonymous) → 202", async () => {
    const w1 = vi.fn();
    expect((await handleIngest(req({ ...base, user_id: "u_9f2a-opaque" }), deps({ bqInsert: w1 }))).status).toBe(202);
    expect(w1).toHaveBeenCalledTimes(1);
    expect((await handleIngest(req({ ...base, user_id: null }), deps())).status).toBe(202);
  });
});
