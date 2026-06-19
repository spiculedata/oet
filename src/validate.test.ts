import { describe, it, expect } from "vitest";
import { validateEnvelope, MAX_EVENTS_PER_BATCH, MAX_PARAM_VALUE_LEN } from "./validate.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const TS = "2026-06-18T00:00:00Z";

const base = {
  client_id: "win-3f2a",
  user_id: null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: "2026-06-18T00:00:00Z",
  events: [{ name: "app_open", ts: TS }],
};

describe("validateEnvelope — happy path & domain laws", () => {
  it("accepts a well-formed, consented, allowlisted envelope", () => {
    const r = validateEnvelope(base, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
    expect(r.accepted).toHaveLength(1);
    expect(r.rejected).toHaveLength(0);
  });

  it("accepts an event with valid flat params", () => {
    const r = validateEnvelope(
      { ...base, events: [{ name: "app_open", ts: TS, params: { source: "win", count: 3, ok: true, note: null } }] },
      DEFAULT_ALLOWLIST,
    );
    expect(r.ok).toBe(true);
    expect(r.accepted).toHaveLength(1);
  });

  it("drops everything when consent is not granted (DOMAIN LAW: opt-in)", () => {
    const r = validateEnvelope({ ...base, consent: false }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.accepted).toHaveLength(0);
    expect(r.rejected).toContain("consent_not_granted");
  });

  it("drops non-allowlisted event names (metric-poison guard)", () => {
    const r = validateEnvelope(
      { ...base, events: [{ name: "spam_evt", ts: TS }] },
      DEFAULT_ALLOWLIST,
    );
    expect(r.ok).toBe(false);
    expect(r.accepted).toHaveLength(0);
    expect(r.rejected).toContain("event_not_allowlisted:spam_evt");
  });
});

describe("validateEnvelope — malformed shape (→ 400)", () => {
  it("rejects a malformed envelope", () => {
    const r = validateEnvelope({ nope: true }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("malformed_envelope");
  });

  it("rejects when an event has a non-string name (type guard)", () => {
    const r = validateEnvelope({ ...base, events: [{ name: 123, ts: TS }] }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("malformed_envelope");
  });

  it("rejects nested/array param values (no nested structures in v1)", () => {
    const r = validateEnvelope(
      { ...base, events: [{ name: "app_open", ts: TS, params: { tags: ["a", "b"] } }] },
      DEFAULT_ALLOWLIST,
    );
    expect(r.rejected).toContain("malformed_envelope");
  });
});

describe("validateEnvelope — envelope field rules (§2.3 → 400)", () => {
  it("rejects a client_id with illegal characters", () => {
    const r = validateEnvelope({ ...base, client_id: "win 3f2a!" }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("invalid_client_id");
  });

  it("rejects a client_id over 128 chars", () => {
    const r = validateEnvelope({ ...base, client_id: "a".repeat(129) }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("invalid_client_id");
  });

  it("rejects an ad-hoc-cased platform token (§2.4)", () => {
    const r = validateEnvelope({ ...base, platform: "Windows" }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("invalid_platform");
  });

  it("rejects a well-formed but UNREGISTERED platform token (SEC C6 poison guard)", () => {
    // "zzz" is a valid lowercase token but not in §2.4 — a format-only check would have let it
    // through and poisoned the platform breakdown. Strict membership rejects it.
    const r = validateEnvelope({ ...base, platform: "zzz" }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("invalid_platform");
  });

  it("accepts every registered §2.4 platform token", () => {
    for (const platform of ["android", "ios", "web", "macos", "windows", "linux", "steam", "cli", "embedded", "server"]) {
      const r = validateEnvelope({ ...base, platform }, DEFAULT_ALLOWLIST);
      expect(r.ok, `platform ${platform} should be accepted`).toBe(true);
    }
  });

  it("rejects an app_version over 64 chars", () => {
    const r = validateEnvelope({ ...base, app_version: "9".repeat(65) }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("invalid_app_version");
  });

  it("rejects an email-shaped user_id → invalid_user_id (PII guard, SEC F3)", () => {
    const r = validateEnvelope({ ...base, user_id: "alice@example.com" }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("invalid_user_id");
  });

  it("rejects a user_id over 128 chars → invalid_user_id", () => {
    const r = validateEnvelope({ ...base, user_id: "u".repeat(129) }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("invalid_user_id");
  });

  it("accepts a valid opaque user_id (and null)", () => {
    expect(validateEnvelope({ ...base, user_id: "u_9f2a-opaque" }, DEFAULT_ALLOWLIST).ok).toBe(true);
    expect(validateEnvelope({ ...base, user_id: null }, DEFAULT_ALLOWLIST).ok).toBe(true);
  });
});

describe("validateEnvelope — batch bounds (§2.1)", () => {
  it("rejects an empty events batch (→ 400)", () => {
    const r = validateEnvelope({ ...base, events: [] }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("batch_empty");
  });

  it("rejects a batch over the cap (→ 413)", () => {
    const events = Array.from({ length: MAX_EVENTS_PER_BATCH + 1 }, () => ({ name: "app_open", ts: TS }));
    const r = validateEnvelope({ ...base, events }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("batch_too_large");
  });

  it("accepts a batch exactly at the cap", () => {
    const events = Array.from({ length: MAX_EVENTS_PER_BATCH }, () => ({ name: "app_open", ts: TS }));
    const r = validateEnvelope({ ...base, events }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
    expect(r.accepted).toHaveLength(MAX_EVENTS_PER_BATCH);
  });
});

describe("validateEnvelope — per-event field rules drop + count (§2.3 → 202)", () => {
  it("drops an event whose name is not snake_case", () => {
    const r = validateEnvelope({ ...base, events: [{ name: "App-Open", ts: TS }] }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.accepted).toHaveLength(0);
    expect(r.rejected).toContain("event_invalid:App-Open:name_charset");
  });

  it("drops an event whose name exceeds 64 chars", () => {
    const name = "a".repeat(65);
    const r = validateEnvelope({ ...base, events: [{ name, ts: TS }] }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain(`event_invalid:${name}:name_length`);
  });

  it("drops an event whose ts has no timezone", () => {
    const r = validateEnvelope({ ...base, events: [{ name: "app_open", ts: "2026-06-18T00:00:00" }] }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("event_invalid:app_open:ts_format");
  });

  it("drops an event with too many params", () => {
    const params: Record<string, number> = {};
    for (let i = 0; i < 26; i++) params[`k_${i}`] = i;
    const r = validateEnvelope({ ...base, events: [{ name: "app_open", ts: TS, params }] }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("event_invalid:app_open:param_count");
  });

  it("drops an event with a non-snake_case param key", () => {
    const r = validateEnvelope(
      { ...base, events: [{ name: "app_open", ts: TS, params: { BadKey: 1 } }] },
      DEFAULT_ALLOWLIST,
    );
    expect(r.rejected).toContain("event_invalid:app_open:param_key_charset");
  });

  it("accepts a string param value at the cap, drops one over it (MAX_PARAM_VALUE_LEN, N1)", () => {
    const atCap = validateEnvelope(
      { ...base, events: [{ name: "app_open", ts: TS, params: { note: "a".repeat(MAX_PARAM_VALUE_LEN) } }] },
      DEFAULT_ALLOWLIST,
    );
    expect(atCap.ok).toBe(true); // 1024 is fine

    const overCap = validateEnvelope(
      { ...base, events: [{ name: "app_open", ts: TS, params: { note: "a".repeat(MAX_PARAM_VALUE_LEN + 1) } }] },
      DEFAULT_ALLOWLIST,
    );
    expect(overCap.ok).toBe(false);
    expect(overCap.accepted).toHaveLength(0);
    expect(overCap.rejected).toContain("event_invalid:app_open:param_value_length");
  });

  it("does not length-cap non-string param values (number/bool/null)", () => {
    const r = validateEnvelope(
      { ...base, events: [{ name: "app_open", ts: TS, params: { big: 1e308, ok: true, none: null } }] },
      DEFAULT_ALLOWLIST,
    );
    expect(r.ok).toBe(true);
  });

  it("keeps good events while dropping bad ones in the same batch", () => {
    const r = validateEnvelope(
      {
        ...base,
        events: [
          { name: "app_open", ts: TS },
          { name: "Bad-Name", ts: TS },
          { name: "purchase", ts: TS },
        ],
      },
      DEFAULT_ALLOWLIST,
    );
    expect(r.ok).toBe(true);
    expect(r.accepted).toHaveLength(2);
    expect(r.rejected).toContain("event_invalid:Bad-Name:name_charset");
  });
});
