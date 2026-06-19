/**
 * QA UNION ALL co-query suite — Spec v0.1 §10 Q3.
 *
 * The §8 union view (`docs/spec/union-view.sql`) stitches the OET destination table together with a
 * first-party GA4 `events_*` export. A BigQuery `UNION ALL` is **column-position + type** based, so it
 * silently breaks (or hard-errors) if the two SELECT legs drift apart in column list, order, or type —
 * or if either leg drifts from `bigquery-schema.json`. The whole "one-line FROM swap" promise (DOMAIN
 * LAW 5) rests on that staying true.
 *
 * SCOPE / HONESTY: this suite does NOT execute BigQuery — running the real view against a real dataset
 * needs a live GCP project, which is gated behind the Owner's GO (authority map). It instead asserts the
 * two things QA *can* verify deterministically and that catch the real failure modes:
 *   (A) STRUCTURAL — parse the SQL: both legs select identical, identically-ordered columns, and that
 *       column list equals the schema. Catches view↔schema and leg↔leg drift.
 *   (B) SHAPE — a real mapper row (toGa4Row) and a mock first-party GA4 row are column-identical and
 *       type-compatible, and `oet_ingest_version` is the working provenance discriminator (NULL vs set).
 * Live co-query validation against BigQuery is deferred to the M5 / deploy step (Owner GO).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { toGa4Row } from "./ga4.js";
import { ENVELOPE_VERSION } from "./envelope.js";
import type { OetEnvelope } from "./envelope.js";

const read = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");
const SQL = read("../docs/spec/union-view.sql");
const SCHEMA: { name: string }[] = JSON.parse(read("../docs/spec/bigquery-schema.json"));
const SCHEMA_COLS = SCHEMA.map((f) => f.name);

/** Pull the ordered column list from each `SELECT … FROM` leg of the view. */
function selectLegColumns(sql: string): string[][] {
  const legs = [...sql.matchAll(/SELECT([\s\S]*?)FROM/gi)];
  return legs.map((m) =>
    m[1]!
      .split("\n")
      .map((line) => line.replace(/--.*$/, "").trim().replace(/,$/, "").trim()) // strip comments + trailing comma
      .filter(Boolean)
      .map((expr) => {
        // `CAST(NULL AS STRING) AS oet_ingest_version` → alias after the LAST " AS "; else the bare ident.
        const parts = expr.split(/\s+AS\s+/i);
        return parts[parts.length - 1]!.replace(/[`;]/g, "").trim();
      }),
  );
}

describe("Q3 (A) — union-view.sql structural conformance", () => {
  const legs = selectLegColumns(SQL);

  it("the view has exactly two UNION ALL legs", () => {
    expect(legs).toHaveLength(2);
    expect(SQL).toMatch(/UNION ALL/);
  });

  it("both legs select identical columns in identical order", () => {
    expect(legs[0]).toEqual(legs[1]);
  });

  it("the leg columns exactly equal bigquery-schema.json (no drift)", () => {
    expect(legs[0]).toEqual(SCHEMA_COLS);
    expect(legs[1]).toEqual(SCHEMA_COLS);
  });

  it("the first-party leg supplies oet_ingest_version as NULL (provenance discriminator)", () => {
    // The OET table HAS the column; the first-party export does not, so the view CASTs NULL for it.
    expect(SQL).toMatch(/CAST\(NULL AS STRING\)\s+AS\s+oet_ingest_version/i);
  });
});

const env: OetEnvelope = {
  client_id: "win-3f2a9c7e",
  user_id: null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: "2026-06-18T12:00:00.000Z",
  events: [{ name: "purchase", ts: "2026-06-18T12:00:00.000Z", params: { source: "win", amount: 4 } }],
};
const ctx = { eventTimestampMicros: 1_750_000_000_000_000, geo: { country: "US", region: null } };

/** A plausible first-party GA4 `events_*` row: same columns, no OET provenance (NULL). */
function mockFirstPartyRow(): Record<string, unknown> {
  return {
    event_name: "session_start",
    event_timestamp: 1_750_000_000_000_001,
    event_params: [{ key: "ga_session_id", value: { int_value: 42 } }],
    user_pseudo_id: "ga-abc123",
    user_id: null,
    platform: "web",
    app_info: { version: "1.0.0" },
    geo: { country: "US", region: "CA" },
    oet_ingest_version: null, // first-party rows carry no OET provenance
  };
}

describe("Q3 (B) — row-shape co-query (real mapper row ⊎ mock first-party row)", () => {
  const oetRow = toGa4Row(env, env.events[0]!, ctx) as unknown as Record<string, unknown>;
  const union = [mockFirstPartyRow(), oetRow];

  it("every row in the union exposes exactly the schema's columns", () => {
    for (const r of union) {
      expect(Object.keys(r).sort()).toEqual([...SCHEMA_COLS].sort());
    }
  });

  it("per column, the two legs are type-compatible (same type, or one is NULL)", () => {
    for (const col of SCHEMA_COLS) {
      const a = (union[0] as Record<string, unknown>)[col];
      const b = (union[1] as Record<string, unknown>)[col];
      if (a === null || b === null) continue; // UNION allows a NULL against any type
      // event_params is an array (REPEATED); JS typeof array is "object", so this holds for it too.
      expect(typeof a, `column ${col} type mismatch across legs`).toBe(typeof b);
    }
  });

  it("oet_ingest_version is the working provenance split: NULL = first-party, set = OET", () => {
    const firstParty = union.filter((r) => r.oet_ingest_version === null);
    const oet = union.filter((r) => r.oet_ingest_version === ENVELOPE_VERSION);
    expect(firstParty).toHaveLength(1);
    expect(oet).toHaveLength(1);
    expect(oet[0]!.event_name).toBe("purchase"); // the OET-sourced row
  });
});
