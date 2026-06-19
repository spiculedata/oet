import { describe, it, expect, vi } from "vitest";
import {
  normalizeAcquisition,
  normalizeAcquisitions,
  runAcquisitionPull,
  ACQUISITION_EVENT,
  type MsStoreAcquisitionRow,
  type AcquisitionSource,
} from "./msstore-puller.js";
import { ENVELOPE_VERSION } from "./envelope.js";

const fullRow: MsStoreAcquisitionRow = {
  date: "2026-06-01",
  acquisitionType: "Free",
  market: "US",
  osVersion: "Windows 11",
  deviceType: "PC",
  storeClient: "Storefront",
  acquisitionQuantity: 123,
};
const DAY_MICROS = Date.parse("2026-06-01T00:00:00Z") * 1000;

function paramMap(row: NonNullable<ReturnType<typeof normalizeAcquisition>>) {
  return Object.fromEntries(row.event_params.map((p) => [p.key, p.value]));
}

describe("normalizeAcquisition — GA4 shape & §8 provenance", () => {
  it("maps an aggregate row to one GA4-shaped row", () => {
    const r = normalizeAcquisition(fullRow)!;
    expect(r.event_name).toBe(ACQUISITION_EVENT); // allowlisted acquisition event
    expect(r.event_timestamp).toBe(DAY_MICROS); // start of the aggregation day (UTC), µs
    expect(r.platform).toBe("windows"); // registered §2.4 token
    expect(r.geo).toEqual({ country: "US", region: null }); // market → country only
    expect(r.user_id).toBeNull();
    expect(r.app_info).toEqual({ version: null }); // acquisitions carry no version
    expect(r.oet_ingest_version).toBe(ENVELOPE_VERSION);
  });

  it("carries the count as a param — does NOT explode the aggregate into N events (LAW 6)", () => {
    const r = normalizeAcquisition(fullRow)!;
    const p = paramMap(r);
    expect(p.acquisition_quantity).toEqual({ int_value: 123 });
    expect(p.acquisition_type).toEqual({ string_value: "Free" });
    expect(p.source).toEqual({ string_value: "msstore_acquisitions" });
  });

  it("uses a deterministic, non-user aggregate key for user_pseudo_id", () => {
    const r = normalizeAcquisition(fullRow)!;
    expect(r.user_pseudo_id).toBe("msstore-agg:2026-06-01:US:Free");
    // Stable across calls (not a random/fabricated GUID).
    expect(normalizeAcquisition(fullRow)!.user_pseudo_id).toBe(r.user_pseudo_id);
  });
});

describe("normalizeAcquisition — DOMAIN LAWS", () => {
  it("PII-free: demographic fields (gender/ageGroup) never enter a row (LAW 1)", () => {
    const withPii = { ...fullRow, gender: "Male", ageGroup: "25-34" } as unknown as MsStoreAcquisitionRow;
    const r = normalizeAcquisition(withPii)!;
    const keys = r.event_params.map((p) => p.key);
    expect(keys).not.toContain("gender");
    expect(keys).not.toContain("age_group");
    expect(keys).not.toContain("ageGroup");
    expect(JSON.stringify(r)).not.toMatch(/male|25-34/i);
  });

  it("gaps stay gaps: absent fields produce no param and null geo/version (LAW 6)", () => {
    const sparse: MsStoreAcquisitionRow = { date: "2026-06-01" };
    const r = normalizeAcquisition(sparse)!;
    expect(r.geo).toBeNull(); // no market
    expect(r.app_info.version).toBeNull();
    const keys = r.event_params.map((p) => p.key);
    expect(keys).toEqual(["source"]); // only the provenance param; nothing invented
  });

  it("skips (returns null) a row with no parseable date — never back-fills time", () => {
    expect(normalizeAcquisition({ date: "" })).toBeNull();
    expect(normalizeAcquisition({ date: "not-a-date" })).toBeNull();
    expect(normalizeAcquisition({ date: "2026-13-40" })).toBeNull(); // impossible date
  });
});

describe("normalizeAcquisitions — batch", () => {
  it("normalizes the placeable rows and counts the skipped ones", () => {
    const { rows, skipped } = normalizeAcquisitions([
      fullRow,
      { date: "bad" },
      { date: "2026-06-02", market: "GB", acquisitionQuantity: 7 },
    ]);
    expect(rows).toHaveLength(2);
    expect(skipped).toBe(1);
    expect(rows.map((r) => r.geo?.country)).toEqual(["US", "GB"]);
  });

  it("emits exactly one row per aggregate input row (no fabrication of individual events)", () => {
    const input = Array.from({ length: 5 }, (_, i) => ({ date: "2026-06-01", market: "US", acquisitionQuantity: 100 + i }));
    expect(normalizeAcquisitions(input).rows).toHaveLength(5);
  });
});

describe("runAcquisitionPull — orchestration", () => {
  function source(rows: MsStoreAcquisitionRow[]): AcquisitionSource {
    return { fetch: vi.fn(async () => rows) };
  }

  it("fetches → normalizes → writes, and reports counts", async () => {
    const bqInsert = vi.fn();
    const res = await runAcquisitionPull("2026-06-01", "2026-06-02", {
      source: source([fullRow, { date: "bad" }]),
      bqInsert,
    });
    expect(res).toEqual({ fetched: 2, written: 1, skipped: 1 });
    expect(bqInsert).toHaveBeenCalledTimes(1);
    expect(bqInsert.mock.calls[0]![0]).toHaveLength(1);
  });

  it("writes NOTHING when the source returns nothing (never invents data)", async () => {
    const bqInsert = vi.fn();
    const res = await runAcquisitionPull("2026-06-01", "2026-06-02", { source: source([]), bqInsert });
    expect(res).toEqual({ fetched: 0, written: 0, skipped: 0 });
    expect(bqInsert).not.toHaveBeenCalled();
  });
});
