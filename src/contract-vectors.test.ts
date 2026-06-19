/**
 * QA contract-vector suite — Spec v0.1 §10 Q1 (canonical rejection-class fixtures).
 *
 * This is QA's first-class acceptance suite for `validateEnvelope`. It deliberately does NOT
 * duplicate the developer tests in `validate.test.ts`; it adds the coverage QA owns:
 *   · exact-limit BOUNDARY vectors (accept at the cap, reject one past it) for every §2.1/§2.3 bound,
 *   · rule classes DEV's suite doesn't exercise (param_key_length, impossible-but-well-formed dates,
 *     offset timezones, empty required scalars),
 *   · the SEC R1 platform-membership requirement, encoded as a skipped acceptance test that flips on
 *     the moment R1 lands (with a companion test pinning today's incorrect behavior so the gap is
 *     executable, not just prose),
 *   · two spec-vs-impl discrepancies pinned as living documentation (see [DISCREPANCY] tags).
 *
 * Every `it` cites the spec clause it nails down. Reason strings are asserted exactly — a silent
 * change to the reason taxonomy (which the endpoint maps to HTTP status, §6) must break a test.
 */
import { describe, it, expect } from "vitest";
import {
  validateEnvelope,
  MAX_CLIENT_ID_LEN,
  MAX_APP_VERSION_LEN,
  MAX_EVENT_NAME_LEN,
  MAX_PARAM_KEYS,
  MAX_PARAM_KEY_LEN,
} from "./validate.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const TS = "2026-06-18T00:00:00Z";

const base = {
  client_id: "win-3f2a",
  user_id: null as string | null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: "2026-06-18T00:00:00Z",
  events: [{ name: "app_open", ts: TS }],
};

// ── §2.3 client_id boundaries ────────────────────────────────────────────────
describe("contract vectors — client_id (§2.3)", () => {
  it("ACCEPTS client_id at exactly the 128-char max", () => {
    const r = validateEnvelope({ ...base, client_id: "a".repeat(MAX_CLIENT_ID_LEN) }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });

  it("REJECTS an empty client_id (length < 1) → invalid_client_id", () => {
    const r = validateEnvelope({ ...base, client_id: "" }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("invalid_client_id");
  });

  it("ACCEPTS the full legal charset [A-Za-z0-9._-]", () => {
    const r = validateEnvelope({ ...base, client_id: "Win-3F2A.9c_7e" }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });
});

// ── §2.3 app_version boundaries ──────────────────────────────────────────────
describe("contract vectors — app_version (§2.3)", () => {
  it("ACCEPTS app_version at exactly the 64-char max", () => {
    const r = validateEnvelope({ ...base, app_version: "9".repeat(MAX_APP_VERSION_LEN) }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });

  it("REJECTS an empty app_version (length < 1) → invalid_app_version", () => {
    const r = validateEnvelope({ ...base, app_version: "" }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("invalid_app_version");
  });
});

// ── §2.4 platform — the SEC R1 poison vector ─────────────────────────────────
describe("contract vectors — platform registered set (§2.4 / SEC R1)", () => {
  it("ACCEPTS a registered token ('windows')", () => {
    const r = validateEnvelope({ ...base, platform: "windows" }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });

  // SEC R1 (tracked as C6), LANDED in slice 2 @ a3b4f21: platform is a stored, queryable,
  // NON-allowlisted dimension, so a well-formed-but-unregistered token poisons the platform
  // breakdown (DOMAIN LAW 3/4). §2.4 is a CLOSED set → membership (REGISTERED_PLATFORMS), not a
  // lowercase-format regex. This is QA's acceptance test for R1.
  it("REJECTS a well-formed but unregistered platform 'zzz' → invalid_platform (SEC R1)", () => {
    const r = validateEnvelope({ ...base, platform: "zzz" }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("invalid_platform");
  });

  it("REJECTS an ad-hoc casing variant 'Windows' (§2.4 forbids ad-hoc casing) → invalid_platform", () => {
    const r = validateEnvelope({ ...base, platform: "Windows" }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("invalid_platform");
  });
});

// ── §2.2 shape — type guard (→ malformed_envelope / 400) ─────────────────────
describe("contract vectors — shape & type guard (§2.2 → 400)", () => {
  it("REJECTS a non-string user_id (must be string | null)", () => {
    const r = validateEnvelope({ ...base, user_id: 123 }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("malformed_envelope");
  });

  it("ACCEPTS a non-null opaque user_id string (§2.3)", () => {
    const r = validateEnvelope({ ...base, user_id: "u_8f31" }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });

  it("REJECTS events that is not an array", () => {
    const r = validateEnvelope({ ...base, events: "app_open" }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("malformed_envelope");
  });

  // [D1 — RESOLVED, SEC-ruled] §2.2/§4.2: consent "false/ABSENT ⇒ nothing retained" is the 202 drop-all
  // path. DEV removed consent from the shape guard so an absent (or non-boolean) consent no longer falls
  // out as malformed_envelope (400); ALL non-true consent now returns consent_not_granted (202), so a
  // prober can't distinguish "missing consent" from "consent:false". This closes the opacity gap.
  it("[D1] treats an ABSENT consent key as consent_not_granted (202), not malformed_envelope (400)", () => {
    const noConsent = { ...base } as Record<string, unknown>;
    delete noConsent.consent;
    const r = validateEnvelope(noConsent, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(false);
    expect(r.rejected).toContain("consent_not_granted");
    expect(r.rejected).not.toContain("malformed_envelope");
  });

  it("[D1] treats a non-boolean consent ('true' string) as consent_not_granted (202), not malformed", () => {
    const r = validateEnvelope({ ...base, consent: "true" }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("consent_not_granted");
    expect(r.rejected).not.toContain("malformed_envelope");
  });
});

// ── §2.3 per-event name boundary ─────────────────────────────────────────────
describe("contract vectors — event name boundary (§2.3)", () => {
  it("ACCEPTS an allowlisted event name at exactly the 64-char max", () => {
    const longName = "a".repeat(MAX_EVENT_NAME_LEN);
    const allow = new Set([...DEFAULT_ALLOWLIST, longName]);
    const r = validateEnvelope({ ...base, events: [{ name: longName, ts: TS }] }, allow);
    expect(r.ok).toBe(true);
    expect(r.accepted).toHaveLength(1);
  });

  it("field rules run BEFORE the allowlist: a non-snake name drops as event_invalid, not not_allowlisted", () => {
    const r = validateEnvelope({ ...base, events: [{ name: "Bad-Name", ts: TS }] }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("event_invalid:Bad-Name:name_charset");
    expect(r.rejected).not.toContain("event_not_allowlisted:Bad-Name");
  });
});

// ── §2.3 ts format ───────────────────────────────────────────────────────────
describe("contract vectors — event ts ISO-8601 (§2.3)", () => {
  it("ACCEPTS an offset timezone (+05:30), not just Z", () => {
    const r = validateEnvelope({ ...base, events: [{ name: "app_open", ts: "2026-06-18T00:00:00+05:30" }] }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });

  it("ACCEPTS fractional seconds", () => {
    const r = validateEnvelope({ ...base, events: [{ name: "app_open", ts: "2026-06-18T00:00:00.123Z" }] }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });

  it("DROPS a well-formed but impossible date (2026-13-40) → event_invalid:...:ts_format", () => {
    const r = validateEnvelope({ ...base, events: [{ name: "app_open", ts: "2026-13-40T00:00:00Z" }] }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("event_invalid:app_open:ts_format");
    expect(r.accepted).toHaveLength(0);
  });
});

// ── §2.3 params boundaries ───────────────────────────────────────────────────
describe("contract vectors — params boundaries (§2.3)", () => {
  it("ACCEPTS exactly MAX_PARAM_KEYS (25) params", () => {
    const params: Record<string, number> = {};
    for (let i = 0; i < MAX_PARAM_KEYS; i++) params[`k_${i}`] = i;
    const r = validateEnvelope({ ...base, events: [{ name: "app_open", ts: TS, params }] }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });

  it("ACCEPTS a param key at exactly the 40-char max", () => {
    const key = "k".repeat(MAX_PARAM_KEY_LEN);
    const r = validateEnvelope({ ...base, events: [{ name: "app_open", ts: TS, params: { [key]: 1 } }] }, DEFAULT_ALLOWLIST);
    expect(r.ok).toBe(true);
  });

  it("DROPS a param key one past the 40-char max → event_invalid:...:param_key_length", () => {
    const key = "k".repeat(MAX_PARAM_KEY_LEN + 1);
    const r = validateEnvelope({ ...base, events: [{ name: "app_open", ts: TS, params: { [key]: 1 } }] }, DEFAULT_ALLOWLIST);
    expect(r.rejected).toContain("event_invalid:app_open:param_key_length");
    expect(r.accepted).toHaveLength(0);
  });
});

// ── §3 / §6 all-dropped opacity ──────────────────────────────────────────────
describe("contract vectors — all-dropped opacity (§3, §6 → 202)", () => {
  it("an envelope where EVERY event is dropped yields accepted:[] (endpoint still returns 202, §6)", () => {
    const r = validateEnvelope(
      { ...base, events: [{ name: "spam_evt", ts: TS }, { name: "also_unknown", ts: TS }] },
      DEFAULT_ALLOWLIST,
    );
    expect(r.ok).toBe(false);
    expect(r.accepted).toHaveLength(0);
    // Both dropped via the allowlist, none written — indistinguishable from a known client to a prober.
    expect(r.rejected).toEqual([
      "event_not_allowlisted:spam_evt",
      "event_not_allowlisted:also_unknown",
    ]);
  });
});
