/**
 * QA GA4-shape conformance suite — Spec v0.1 §10 Q2.
 *
 * DEV's ga4.test.ts already asserts the produced row's TOP-LEVEL columns match
 * `bigquery-schema.json` and spot-checks field mapping. This suite is QA's deeper,
 * schema-DRIVEN conformance engine: a single recursive validator walks the actual
 * `docs/spec/bigquery-schema.json` and asserts a produced row conforms at EVERY level —
 *   · type per column (STRING→string, INT64→integer, FLOAT64→number, BOOL→boolean, RECORD→object),
 *   · mode per column (REQUIRED non-null · NULLABLE may be null · REPEATED is an array of records),
 *   · NO EXTRA KEYS at any nesting level — the PII-leak guard (DOMAIN LAW 1): a stray `ip` inside
 *     `geo`, or any unspecified nested field, fails the gate. DEV's top-level check cannot catch a
 *     nested leak; this can.
 *
 * The validator is contract-driven: if the schema changes, conformance re-derives from it — no
 * hand-maintained mirror to drift. Reusable for the endpoint slice + pullers (they emit the same row).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { toGa4Row, paramToGa4Value } from "./ga4.js";
import type { OetEnvelope } from "./envelope.js";

interface SchemaField {
  name: string;
  type: "STRING" | "INT64" | "FLOAT64" | "BOOL" | "RECORD";
  mode: "REQUIRED" | "NULLABLE" | "REPEATED";
  fields?: SchemaField[];
}
const SCHEMA: SchemaField[] = JSON.parse(
  readFileSync(fileURLToPath(new URL("../docs/spec/bigquery-schema.json", import.meta.url)), "utf8"),
);

/** Assert one scalar/record value conforms to one schema field's type. `path` is for failure messages. */
function assertValueType(value: unknown, field: SchemaField, path: string): void {
  switch (field.type) {
    case "STRING":
      expect(typeof value, `${path} should be STRING`).toBe("string");
      break;
    case "INT64":
      expect(Number.isInteger(value), `${path} should be an INT64 integer`).toBe(true);
      break;
    case "FLOAT64":
      expect(typeof value, `${path} should be FLOAT64`).toBe("number");
      break;
    case "BOOL":
      expect(typeof value, `${path} should be BOOL`).toBe("boolean");
      break;
    case "RECORD":
      expect(typeof value === "object" && value !== null && !Array.isArray(value), `${path} should be a RECORD object`).toBe(true);
      assertRecordConforms(value as Record<string, unknown>, field.fields ?? [], path);
      break;
  }
}

/** Recursively assert a record object conforms to a set of schema fields — incl. NO EXTRA KEYS. */
function assertRecordConforms(obj: Record<string, unknown>, fields: SchemaField[], path: string): void {
  const allowed = new Set(fields.map((f) => f.name));
  // PII-leak guard: every key present must be declared in the schema at this level.
  for (const key of Object.keys(obj)) {
    expect(allowed.has(key), `${path}.${key} is NOT in the schema (possible leak / drift)`).toBe(true);
  }
  for (const field of fields) {
    const value = obj[field.name];
    const fpath = `${path}.${field.name}`;
    if (field.mode === "REPEATED") {
      expect(Array.isArray(value), `${fpath} (REPEATED) should be an array`).toBe(true);
      for (let i = 0; i < (value as unknown[]).length; i++) {
        assertValueType((value as unknown[])[i], { ...field, mode: "REQUIRED" }, `${fpath}[${i}]`);
      }
      continue;
    }
    if (value === null || value === undefined) {
      expect(field.mode, `${fpath} is null but schema says REQUIRED`).not.toBe("REQUIRED");
      continue; // NULLABLE null is fine
    }
    assertValueType(value, field, fpath);
  }
}

const env: OetEnvelope = {
  client_id: "win-3f2a9c7e",
  user_id: "u_opaque_1",
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: "2026-06-18T12:00:00.000Z",
  events: [
    {
      name: "purchase",
      ts: "2026-06-18T12:00:00.000Z",
      params: { source: "win", amount: 4, total: 12.5, paid: true, note: null },
    },
  ],
};
const ctx = { eventTimestampMicros: 1_750_000_000_000_000, geo: { country: "US", region: "CA" } };

describe("Q2 — recursive schema conformance (every level)", () => {
  it("a fully-populated row conforms to bigquery-schema.json at every nesting level", () => {
    const r = toGa4Row(env, env.events[0]!, ctx) as unknown as Record<string, unknown>;
    assertRecordConforms(r, SCHEMA, "row");
  });

  it("a minimal row (anon user, no geo, no params) still conforms", () => {
    const bare: OetEnvelope = { ...env, user_id: null, events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }] };
    const r = toGa4Row(bare, bare.events[0]!, { eventTimestampMicros: 1 }) as unknown as Record<string, unknown>;
    assertRecordConforms(r, SCHEMA, "row");
  });

  it("every param JS type round-trips into a schema-conformant event_params record", () => {
    const allTypes: OetEnvelope = {
      ...env,
      events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z", params: { s: "x", i: 9, d: 1.5, b: false, n: null } }],
    };
    const r = toGa4Row(allTypes, allTypes.events[0]!, ctx) as unknown as Record<string, unknown>;
    assertRecordConforms(r, SCHEMA, "row");
  });
});

describe("Q2 — nested PII-leak guard (DOMAIN LAW 1)", () => {
  it("geo carries ONLY {country, region} — a raw-IP key would fail conformance", () => {
    const r = toGa4Row(env, env.events[0]!, ctx);
    expect(Object.keys(r.geo ?? {}).sort()).toEqual(["country", "region"]);
    // Prove the guard bites: inject a leak and confirm the validator rejects it.
    const leaked = { ...r, geo: { ...r.geo, ip: "203.0.113.7" } } as unknown as Record<string, unknown>;
    expect(() => assertRecordConforms(leaked, SCHEMA, "row")).toThrow(/NOT in the schema/);
  });

  it("an extra top-level column also fails conformance (drift guard)", () => {
    const r = toGa4Row(env, env.events[0]!, ctx);
    const drifted = { ...r, raw_user_email: "a@b.com" } as unknown as Record<string, unknown>;
    expect(() => assertRecordConforms(drifted, SCHEMA, "row")).toThrow(/NOT in the schema/);
  });
});

describe("Q2 — typed value sub-record invariant (GA4 semantics)", () => {
  it("each non-null param value sets exactly ONE typed field, named per schema", () => {
    const valueFields = SCHEMA.find((f) => f.name === "event_params")!.fields!.find((f) => f.name === "value")!.fields!;
    const allowed = new Set(valueFields.map((f) => f.name)); // string_value/int_value/double_value/bool_value
    const r = toGa4Row(env, env.events[0]!, ctx);
    for (const p of r.event_params) {
      if (p.value === null) continue;
      const keys = Object.keys(p.value);
      expect(keys.length, `param ${p.key}: exactly one typed field`).toBe(1);
      expect(allowed.has(keys[0]!), `param ${p.key}: typed field ${keys[0]} in schema`).toBe(true);
    }
  });

  it("integer → int_value (INT64), non-integer → double_value (FLOAT64)", () => {
    expect(paramToGa4Value(42)).toEqual({ int_value: 42 });
    expect(paramToGa4Value(-7)).toEqual({ int_value: -7 });
    expect(paramToGa4Value(0.5)).toEqual({ double_value: 0.5 });
  });
});

describe("Q2 — INT64 range edge [finding N-Q2-1, RESOLVED by DEV]", () => {
  // BigQuery INT64 max is 9_223_372_036_854_775_807 (~9.2e18). JS Number.isInteger(1e21) is true, so the
  // mapper used to classify 1e21 as { int_value: 1e21 } — which OVERFLOWS BQ INT64 and would corrupt the
  // streaming insert. DEV applied the recommended guard: only Number.isSafeInteger values map to int_value;
  // anything beyond ±MAX_SAFE_INTEGER routes to double_value (FLOAT64), which JS can represent and BQ accepts.
  it("routes an integer beyond the safe range to double_value, not int_value (no BQ INT64 overflow)", () => {
    const beyondInt64 = 1e21;
    expect(Number.isInteger(beyondInt64)).toBe(true);
    expect(beyondInt64).toBeGreaterThan(Number.MAX_SAFE_INTEGER); // the former danger zone
    expect(paramToGa4Value(beyondInt64)).toEqual({ double_value: beyondInt64 });
  });

  it("still maps safe-range integers to int_value (boundary at MAX_SAFE_INTEGER)", () => {
    expect(paramToGa4Value(Number.MAX_SAFE_INTEGER)).toEqual({ int_value: Number.MAX_SAFE_INTEGER });
    expect(paramToGa4Value(Number.MAX_SAFE_INTEGER + 1)).toEqual({ double_value: Number.MAX_SAFE_INTEGER + 1 });
  });
});
