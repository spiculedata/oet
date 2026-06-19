import { describe, it, expect } from "vitest";
import { canonicalize, canonicalEnvelope } from "./canonical.js";

describe("canonicalize — §5.2 deterministic serialization", () => {
  it("sorts object keys lexicographically", () => {
    expect(canonicalize({ b: 1, a: 2, c: 3 })).toBe('{"a":2,"b":1,"c":3}');
  });

  it("sorts keys at EVERY nesting level", () => {
    expect(canonicalize({ z: { y: 1, x: 2 }, a: [{ d: 4, c: 3 }] })).toBe(
      '{"a":[{"c":3,"d":4}],"z":{"x":2,"y":1}}',
    );
  });

  it("is independent of input key order (the whole point — both sides agree)", () => {
    const a = canonicalize({ one: 1, two: 2, three: { nested: true, also: "x" } });
    const b = canonicalize({ three: { also: "x", nested: true }, two: 2, one: 1 });
    expect(a).toBe(b);
  });

  it("preserves array order (arrays are ordered; only object keys sort)", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  it("emits no insignificant whitespace", () => {
    expect(canonicalize({ a: 1, b: [1, 2] })).not.toMatch(/\s/);
  });

  it("serializes scalars like JSON (with string escaping)", () => {
    expect(canonicalize("a\"b\n")).toBe(JSON.stringify("a\"b\n"));
    expect(canonicalize(12.5)).toBe("12.5");
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(null)).toBe("null");
  });

  it("serializes non-finite numbers to null (matches JSON.stringify)", () => {
    expect(canonicalize(NaN)).toBe("null");
    expect(canonicalize(Infinity)).toBe("null");
  });

  it("drops undefined-valued keys", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it("is not fooled by integer-like keys (built by hand, not JSON.stringify order)", () => {
    // V8 would iterate "2" before "10" before "a" in JSON.stringify; lexicographic sort gives "10","2","a".
    expect(canonicalize({ "10": 0, "2": 0, a: 0 })).toBe('{"10":0,"2":0,"a":0}');
  });
});

describe("canonicalEnvelope — §5.2 signing payload", () => {
  const env = {
    client_id: "win-3f2a",
    user_id: null,
    platform: "windows",
    app_version: "2.2.0+27",
    consent: true,
    events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z", params: { source: "win" } }],
    sig: "hmac-sha256:abc123",
  };

  it("removes the sig field before canonicalizing", () => {
    expect(canonicalEnvelope(env)).not.toContain("sig");
    expect(canonicalEnvelope(env)).not.toContain("abc123");
  });

  it("INCLUDES sent_at in the signed payload (§5.5 — so the freshness anchor is tamper-proof)", () => {
    const signed = canonicalEnvelope({ ...env, sent_at: "2026-06-18T00:00:01Z" });
    expect(signed).toContain('"sent_at":"2026-06-18T00:00:01Z"');
    // changing sent_at changes the canonical payload → changes the HMAC → can't be forged.
    expect(signed).not.toBe(canonicalEnvelope({ ...env, sent_at: "2026-06-18T09:00:00Z" }));
  });

  it("produces the identical payload whether or not sig is present (sig-independent)", () => {
    const withSig = canonicalEnvelope(env);
    const noSig = canonicalEnvelope({ ...env, sig: undefined as unknown as string });
    const everDifferentSig = canonicalEnvelope({ ...env, sig: "hmac-sha256:DIFFERENT" });
    expect(withSig).toBe(noSig);
    expect(withSig).toBe(everDifferentSig);
  });

  it("does not mutate the caller's envelope", () => {
    const copy = { ...env };
    canonicalEnvelope(env);
    expect(env).toEqual(copy);
    expect(env.sig).toBe("hmac-sha256:abc123");
  });

  it("emitter and server derive the SAME canonical string from the same envelope (QA Q4 premise)", () => {
    // Same logical envelope, fields supplied in a different order — must canonicalize identically.
    const serverSide = canonicalEnvelope(env);
    const emitterSide = canonicalEnvelope({
      events: [{ ts: "2026-06-18T00:00:00Z", params: { source: "win" }, name: "app_open" }],
      consent: true,
      sig: "hmac-sha256:abc123",
      platform: "windows",
      app_version: "2.2.0+27",
      client_id: "win-3f2a",
      user_id: null,
    });
    expect(emitterSide).toBe(serverSide);
  });
});
