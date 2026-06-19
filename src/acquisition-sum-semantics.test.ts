/**
 * QA — acquisition aggregate query semantics (Spec v0.1.1 §8.1, normative; gate question Q3').
 *
 * The MS Store puller emits ONE GA4 row per (date, market, …) bucket with the bucket count in the
 * `acquisition_quantity` param (LAW 6 — never explode an aggregate into N synthetic per-user rows).
 * v0.1.1 §8.1 therefore makes a query rule NORMATIVE for every consumer:
 *
 *     Acquisition metrics MUST be computed as SUM(acquisition_quantity), NEVER COUNT(*).
 *
 * This suite proves the rule is real and necessary on actual rows: COUNT(*) over acquisition rows
 * counts BUCKETS (undercounts by orders of magnitude), while SUM(acquisition_quantity) gives the true
 * total; and runtime-usage rows (one per event) are unaffected. It's the executable form of the §8.1
 * contract the M5 dashboards must honor — QA will re-assert it against real SQL at M5.
 */
import { describe, it, expect } from "vitest";
import { normalizeAcquisitions, type MsStoreAcquisitionRow } from "./msstore-puller.js";
import { toGa4Row } from "./ga4.js";
import type { Ga4Row } from "./ga4.js";
import type { OetEnvelope } from "./envelope.js";

/** SQL `SUM((SELECT value.int_value FROM UNNEST(event_params) WHERE key='acquisition_quantity'))`, in JS. */
function sumAcquisitionQuantity(rows: Ga4Row[]): number {
  return rows.reduce((acc, r) => {
    const p = r.event_params.find((p) => p.key === "acquisition_quantity");
    const v = p && p.value && "int_value" in p.value ? p.value.int_value : 0;
    return acc + (v ?? 0);
  }, 0);
}
const where = (rows: Ga4Row[], pred: (r: Ga4Row) => boolean) => rows.filter(pred);

// 3 acquisition buckets totalling 357 downloads, + 4 runtime app_open events (1 row each).
const acquisitionInput: MsStoreAcquisitionRow[] = [
  { date: "2026-06-01", market: "US", acquisitionQuantity: 100 },
  { date: "2026-06-01", market: "GB", acquisitionQuantity: 250 },
  { date: "2026-06-02", market: "US", acquisitionQuantity: 7 },
];
const TRUE_DOWNLOAD_TOTAL = 357;

const runtimeEnv: OetEnvelope = {
  client_id: "win-1", user_id: null, platform: "windows", app_version: "2.0.0",
  consent: true, events: [{ name: "app_open", ts: "2026-06-01T00:00:00Z" }],
};

function mixedTable(): Ga4Row[] {
  const acq = normalizeAcquisitions(acquisitionInput).rows;
  const runtime = Array.from({ length: 4 }, () => toGa4Row(runtimeEnv, runtimeEnv.events[0]!, { eventTimestampMicros: 1 }));
  return [...acq, ...runtime];
}

describe("v0.1.1 §8.1 — acquisition metrics: SUM(acquisition_quantity), never COUNT(*)", () => {
  it("SUM(acquisition_quantity) over store_download rows yields the true download total", () => {
    const downloads = where(mixedTable(), (r) => r.event_name === "store_download");
    expect(sumAcquisitionQuantity(downloads)).toBe(TRUE_DOWNLOAD_TOTAL); // 357
  });

  it("COUNT(*) over the same rows counts BUCKETS, not downloads — and is WRONG", () => {
    const downloads = where(mixedTable(), (r) => r.event_name === "store_download");
    expect(downloads.length).toBe(3); // 3 buckets
    expect(downloads.length).not.toBe(TRUE_DOWNLOAD_TOTAL); // 3 ≠ 357 — COUNT(*) undercounts massively
  });

  it("acquisition rows are self-identifying (event_name + msstore-agg id prefix) so consumers can tell them apart", () => {
    const table = mixedTable();
    const acq = where(table, (r) => r.event_name === "store_download");
    expect(acq.every((r) => r.user_pseudo_id.startsWith("msstore-agg:"))).toBe(true);
    expect(where(table, (r) => r.event_name === "app_open").every((r) => !r.user_pseudo_id.startsWith("msstore-agg:"))).toBe(true);
  });

  it("runtime-usage rows are unaffected: COUNT(*) is correct for one-row-per-event data", () => {
    const opens = where(mixedTable(), (r) => r.event_name === "app_open");
    expect(opens.length).toBe(4); // 4 events → 4 rows → COUNT(*) = 4 is right here
  });
});
