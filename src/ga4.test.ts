import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { toGa4Row, toGa4Rows, paramToGa4Value, type Ga4Row } from "./ga4.js";
import { ENVELOPE_VERSION } from "./envelope.js";
import type { OetEnvelope } from "./envelope.js";

// The schema is the contract. We assert produced rows conform to it byte-shape (QA Q2).
interface SchemaField {
  name: string;
  type: string;
  mode: string;
  fields?: SchemaField[];
}
const schemaPath = fileURLToPath(
  new URL("../docs/spec/bigquery-schema.json", import.meta.url),
);
const SCHEMA: SchemaField[] = JSON.parse(readFileSync(schemaPath, "utf8"));

const env: OetEnvelope = {
  client_id: "win-3f2a9c7e",
  user_id: null,
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
const ctx = { eventTimestampMicros: 1_750_000_000_000_000, geo: { country: "US", region: null } };

function row(): Ga4Row {
  return toGa4Row(env, env.events[0]!, ctx);
}

describe("toGa4Row — GA4 schema conformance (QA Q2)", () => {
  it("produces exactly the schema's top-level columns — no missing, no extra", () => {
    const r = row();
    const schemaCols = SCHEMA.map((f) => f.name).sort();
    const rowCols = Object.keys(r).sort();
    expect(rowCols).toEqual(schemaCols);
  });

  it("every REQUIRED column is present and non-null", () => {
    const r = row() as unknown as Record<string, unknown>;
    for (const f of SCHEMA.filter((f) => f.mode === "REQUIRED")) {
      expect(r[f.name], `REQUIRED column ${f.name}`).not.toBeNull();
      expect(r[f.name], `REQUIRED column ${f.name}`).not.toBeUndefined();
    }
  });

  it("maps the GA4-shaped scalar columns with correct JS types", () => {
    const r = row();
    expect(typeof r.event_name).toBe("string");
    expect(Number.isInteger(r.event_timestamp)).toBe(true);
    expect(typeof r.user_pseudo_id).toBe("string");
    expect(typeof r.platform).toBe("string");
    expect(typeof r.oet_ingest_version).toBe("string");
    expect(Array.isArray(r.event_params)).toBe(true);
  });
});

describe("toGa4Row — §8 field mapping", () => {
  it("maps envelope identity fields to their GA4 columns", () => {
    const r = row();
    expect(r.event_name).toBe("purchase");
    expect(r.user_pseudo_id).toBe("win-3f2a9c7e"); // client_id → user_pseudo_id
    expect(r.user_id).toBeNull();
    expect(r.platform).toBe("windows");
    expect(r.app_info).toEqual({ version: "2.2.0+27" });
    expect(r.oet_ingest_version).toBe(ENVELOPE_VERSION);
  });

  it("uses the SERVER timestamp, never the client's advisory ts (§2.5)", () => {
    const r = row();
    expect(r.event_timestamp).toBe(1_750_000_000_000_000);
  });

  it("preserves the client ts as the first client_ts param", () => {
    const r = row();
    expect(r.event_params[0]).toEqual({
      key: "client_ts",
      value: { string_value: "2026-06-18T12:00:00.000Z" },
    });
  });

  it("maps each param value to its GA4 typed sub-record", () => {
    const r = row();
    const byKey = Object.fromEntries(r.event_params.map((p) => [p.key, p.value]));
    expect(byKey.source).toEqual({ string_value: "win" });
    expect(byKey.amount).toEqual({ int_value: 4 }); // integer → int_value
    expect(byKey.total).toEqual({ double_value: 12.5 }); // non-integer → double_value
    expect(byKey.paid).toEqual({ bool_value: true });
    expect(byKey.note).toBeNull(); // null param → null value record
  });
});

describe("paramToGa4Value", () => {
  it("distinguishes int from double", () => {
    expect(paramToGa4Value(7)).toEqual({ int_value: 7 });
    expect(paramToGa4Value(7.5)).toEqual({ double_value: 7.5 });
  });
  it("routes out-of-safe-range integers to double_value, not int_value (N-Q2-1, BQ INT64 overflow)", () => {
    expect(paramToGa4Value(1e21)).toEqual({ double_value: 1e21 });
    expect(paramToGa4Value(Number.MAX_SAFE_INTEGER)).toEqual({ int_value: Number.MAX_SAFE_INTEGER });
    expect(paramToGa4Value(Number.MAX_SAFE_INTEGER + 1)).toEqual({ double_value: Number.MAX_SAFE_INTEGER + 1 });
    expect(paramToGa4Value(-1e21)).toEqual({ double_value: -1e21 });
  });
  it("maps string, bool, and null", () => {
    expect(paramToGa4Value("x")).toEqual({ string_value: "x" });
    expect(paramToGa4Value(false)).toEqual({ bool_value: false });
    expect(paramToGa4Value(null)).toBeNull();
  });
});

describe("toGa4Row — geo & enrichment", () => {
  it("sets geo to null when no geo is derived (raw IP never present)", () => {
    const r = toGa4Row(env, env.events[0]!, { eventTimestampMicros: 1 });
    expect(r.geo).toBeNull();
  });
  it("normalizes a partial geo to {country, region} with null fill", () => {
    const r = row();
    expect(r.geo).toEqual({ country: "US", region: null });
  });
  it("emits only the client_ts param when the event has no params", () => {
    const bare: OetEnvelope = { ...env, events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }] };
    const r = toGa4Row(bare, bare.events[0]!, ctx);
    expect(r.event_params).toHaveLength(1);
    expect(r.event_params[0]!.key).toBe("client_ts");
  });
});

describe("toGa4Rows", () => {
  it("maps every event sharing one enrichment context", () => {
    const multi: OetEnvelope = {
      ...env,
      events: [
        { name: "app_open", ts: "2026-06-18T00:00:00Z" },
        { name: "purchase", ts: "2026-06-18T00:00:01Z" },
      ],
    };
    const rows = toGa4Rows(multi, multi.events, ctx);
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.event_name)).toEqual(["app_open", "purchase"]);
    expect(rows.every((r) => r.event_timestamp === ctx.eventTimestampMicros)).toBe(true);
  });
});
