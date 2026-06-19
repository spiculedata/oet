/**
 * QA M3 conformance gate — MS Store puller rows are GA4-shaped & union-compatible (Spec §5,§8; LAW 5/6).
 *
 * SEC's M3 gate explicitly assigned GA4-shape CONFORMANCE to QA: a puller only earns its place if its
 * rows land in the SAME table and flow through the §8 UNION ALL view alongside runtime events. DEV's
 * msstore-puller.test.ts checks individual fields; this suite proves the deeper guarantee:
 *   · a normalized acquisition row conforms to `bigquery-schema.json` at EVERY nesting level
 *     (type/mode/no-extra-keys) — the same schema-driven validator QA uses for runtime rows (Q2);
 *   · a puller row and a runtime `toGa4Row` row expose the IDENTICAL column set → they co-query through
 *     the union with no type/column drift (the puller's entire reason to exist);
 *   · LAW-6/PII conformance that the schema check enforces structurally: injected demographics can't add
 *     a column, and the count survives as a SUM-able INT64 param (SEC: downstream SUMs, never COUNTs).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { normalizeAcquisition, normalizeAcquisitions, ACQUISITION_EVENT, type MsStoreAcquisitionRow } from "./msstore-puller.js";
import { toGa4Row } from "./ga4.js";
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
const SCHEMA_COLS = SCHEMA.map((f) => f.name);

// Schema-driven recursive validator (same contract QA enforces for runtime rows in ga4-conformance).
function assertValueType(value: unknown, field: SchemaField, path: string): void {
  switch (field.type) {
    case "STRING": expect(typeof value, `${path} STRING`).toBe("string"); break;
    case "INT64": expect(Number.isInteger(value), `${path} INT64`).toBe(true); break;
    case "FLOAT64": expect(typeof value, `${path} FLOAT64`).toBe("number"); break;
    case "BOOL": expect(typeof value, `${path} BOOL`).toBe("boolean"); break;
    case "RECORD":
      expect(typeof value === "object" && value !== null && !Array.isArray(value), `${path} RECORD`).toBe(true);
      assertRecordConforms(value as Record<string, unknown>, field.fields ?? [], path);
      break;
  }
}
function assertRecordConforms(obj: Record<string, unknown>, fields: SchemaField[], path: string): void {
  const allowed = new Set(fields.map((f) => f.name));
  for (const key of Object.keys(obj)) {
    expect(allowed.has(key), `${path}.${key} NOT in schema (leak/drift)`).toBe(true);
  }
  for (const field of fields) {
    const value = obj[field.name];
    const fpath = `${path}.${field.name}`;
    if (field.mode === "REPEATED") {
      expect(Array.isArray(value), `${fpath} REPEATED`).toBe(true);
      for (let i = 0; i < (value as unknown[]).length; i++) assertValueType((value as unknown[])[i], { ...field, mode: "REQUIRED" }, `${fpath}[${i}]`);
      continue;
    }
    if (value === null || value === undefined) { expect(field.mode, `${fpath} null`).not.toBe("REQUIRED"); continue; }
    assertValueType(value, field, fpath);
  }
}

const fullRow: MsStoreAcquisitionRow = {
  date: "2026-06-01", acquisitionType: "Free", market: "US",
  osVersion: "Windows 11", deviceType: "PC", storeClient: "Storefront", acquisitionQuantity: 123,
};

describe("M3 — puller row conforms to bigquery-schema.json (every level)", () => {
  it("a full acquisition row conforms structurally to the GA4 schema", () => {
    const r = normalizeAcquisition(fullRow)! as unknown as Record<string, unknown>;
    assertRecordConforms(r, SCHEMA, "row");
  });

  it("a sparse acquisition row (only date) still conforms", () => {
    const r = normalizeAcquisition({ date: "2026-06-01" })! as unknown as Record<string, unknown>;
    assertRecordConforms(r, SCHEMA, "row");
  });

  it("injected demographics cannot add a column — the row still conforms (PII-free structurally)", () => {
    const withPii = { ...fullRow, gender: "Male", ageGroup: "25-34" } as unknown as MsStoreAcquisitionRow;
    const r = normalizeAcquisition(withPii)! as unknown as Record<string, unknown>;
    assertRecordConforms(r, SCHEMA, "row"); // would throw on any stray gender/age_group column
    expect(JSON.stringify(r)).not.toMatch(/male|25-34/i);
  });
});

describe("M3 — union-compatibility with runtime rows (LAW 5)", () => {
  const runtimeEnv: OetEnvelope = {
    client_id: "win-1", user_id: null, platform: "windows", app_version: "2.0.0",
    consent: true, events: [{ name: "app_open", ts: "2026-06-01T00:00:00Z" }],
  };
  it("a puller row and a runtime toGa4Row row expose the IDENTICAL column set", () => {
    const pullerRow = normalizeAcquisition(fullRow)!;
    const runtimeRow = toGa4Row(runtimeEnv, runtimeEnv.events[0]!, { eventTimestampMicros: 1 });
    const cols = (o: object) => Object.keys(o).sort();
    expect(cols(pullerRow)).toEqual([...SCHEMA_COLS].sort()); // == schema…
    expect(cols(pullerRow)).toEqual(cols(runtimeRow)); // …== runtime → co-queryable in the union
  });

  it("oet_ingest_version stamps the puller row (provenance distinguishes it downstream)", () => {
    expect(normalizeAcquisition(fullRow)!.oet_ingest_version).toBe("oet.event.v1");
  });
});

describe("M3 — SEC rulings as conformance assertions", () => {
  it("event_name is the allowlisted constant 'store_download' (ruling b), source cannot override it", () => {
    expect(ACQUISITION_EVENT).toBe("store_download");
    // Even if the source supplies odd fields, event_name is a compile-time constant, not source-derived.
    const r = normalizeAcquisition({ ...fullRow, acquisitionType: "store_install" as string })!;
    expect(r.event_name).toBe("store_download");
  });

  it("platform is the registered §2.4 token 'windows'", () => {
    expect(normalizeAcquisition(fullRow)!.platform).toBe("windows");
  });

  it("the count is one SUM-able INT64 param — aggregate kept as ONE row, not exploded (ruling a / LAW 6)", () => {
    const r = normalizeAcquisition(fullRow)!;
    const qty = r.event_params.find((p) => p.key === "acquisition_quantity");
    expect(qty?.value).toEqual({ int_value: 123 }); // INT64 → downstream SUM(...int_value), never COUNT(*)
    // 123 acquisitions → exactly ONE row (no fabricated per-user events).
    expect(normalizeAcquisitions([fullRow]).rows).toHaveLength(1);
  });
});
