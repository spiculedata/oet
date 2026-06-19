/**
 * Microsoft Store Analytics puller (Spec §1 "Acquisition", M3) — pure normalizer core.
 *
 * Acquisition data (downloads/installs/store conversions) happens OUTSIDE the app, so no emitter
 * sees it. A scheduled server-side puller fetches it from the MS Store Analytics REST API and
 * normalizes it to the SAME GA4-shaped row as runtime events, so it lands in the same table and
 * flows through the §8 UNION ALL view automatically.
 *
 * DOMAIN LAWS that bind a puller specifically:
 *  - **Never fabricate or guess (LAW 6).** The MS Store API returns AGGREGATE rows (e.g. "123
 *    acquisitions in US on 2026-06-01"), NOT individual events. We do NOT explode an aggregate into
 *    123 synthetic per-user events — that would invent users/ids that never existed. We emit ONE row
 *    per aggregate bucket and carry the count as a param. A row we can't place in time (no parseable
 *    date) is SKIPPED, not back-filled. Absent fields stay null — gaps stay gaps.
 *  - **PII-free (LAW 1).** The API also returns `gender` and `ageGroup` (demographics). Those are
 *    deliberately NOT mapped — they never enter a row. Geo is `market` (country) only; no region.
 *  - The puller writes server-side under least-priv IAM (SEC ruling #5) — no HMAC/consent path; but
 *    it still emits only allowlisted event names and PII-free rows.
 *
 * This module is pure + unit-testable. Fetching (OAuth + paginated HTTP to the real Store API) and
 * the BigQuery write are injected (`AcquisitionSource`, `bqInsert`) — real creds/endpoints wait for
 * Owner GO; until then it runs against fixtures / the emulator.
 */

import { ENVELOPE_VERSION } from "./envelope.js";
import { paramToGa4Value } from "./ga4.js";
import type { Ga4Param, Ga4Row } from "./ga4.js";

/** Event name emitted for a Store acquisition. Must be in the deployment allowlist (§3). */
export const ACQUISITION_EVENT = "store_download";

/**
 * One AGGREGATE row from the MS Store Analytics acquisitions endpoint. Only the non-PII fields we
 * map are typed here; `gender`/`ageGroup` are intentionally omitted (PII, never mapped).
 * All fields beyond `date` are optional — the source omits what it doesn't have, and so do we.
 */
export interface MsStoreAcquisitionRow {
  /** Aggregation day, "YYYY-MM-DD" (UTC). Required to place the event in time. */
  date: string;
  acquisitionType?: string; // Free | Trial | Paid
  market?: string; // ISO country
  osVersion?: string;
  deviceType?: string;
  storeClient?: string;
  acquisitionQuantity?: number;
}

/** Microseconds since epoch for the START of the given UTC day, or null if the date is unparseable. */
function dayStartMicros(date: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
  const ms = Date.parse(`${date}T00:00:00Z`);
  return Number.isNaN(ms) ? null : ms * 1000;
}

/**
 * Normalize one MS Store aggregate acquisition row to a GA4-shaped row, or null if it can't be
 * placed in time (gap stays gap — never fabricated). `user_pseudo_id` is a deterministic, clearly
 * NON-user aggregate key (there is no real user behind an aggregate); provenance is on every row via
 * `oet_ingest_version`. Only fields the source actually returned become params.
 */
export function normalizeAcquisition(row: MsStoreAcquisitionRow): Ga4Row | null {
  const eventTimestamp = dayStartMicros(row.date);
  if (eventTimestamp === null) return null;

  // Deterministic aggregate key — NOT a user id. Stable per (day, market, acquisitionType) bucket.
  const aggKey = `msstore-agg:${row.date}:${row.market ?? "?"}:${row.acquisitionType ?? "?"}`;

  const params: Ga4Param[] = [{ key: "source", value: { string_value: "msstore_acquisitions" } }];
  const addStr = (key: string, v: string | undefined): void => {
    if (v !== undefined) params.push({ key, value: paramToGa4Value(v) });
  };
  const addNum = (key: string, v: number | undefined): void => {
    if (v !== undefined) params.push({ key, value: paramToGa4Value(v) });
  };
  addStr("acquisition_type", row.acquisitionType);
  addStr("os_version", row.osVersion);
  addStr("device_type", row.deviceType);
  addStr("store_client", row.storeClient);
  addNum("acquisition_quantity", row.acquisitionQuantity);

  return {
    event_name: ACQUISITION_EVENT,
    event_timestamp: eventTimestamp,
    event_params: params,
    user_pseudo_id: aggKey,
    user_id: null,
    platform: "windows", // MS Store = Windows; a registered §2.4 token
    app_info: { version: null }, // acquisitions carry no app version — gap stays gap
    geo: row.market !== undefined ? { country: row.market, region: null } : null,
    oet_ingest_version: ENVELOPE_VERSION,
  };
}

/** Normalize a batch, dropping rows that can't be placed in time (and counting them for the caller). */
export function normalizeAcquisitions(rows: readonly MsStoreAcquisitionRow[]): {
  rows: Ga4Row[];
  skipped: number;
} {
  const out: Ga4Row[] = [];
  let skipped = 0;
  for (const r of rows) {
    const row = normalizeAcquisition(r);
    if (row === null) skipped++;
    else out.push(row);
  }
  return { rows: out, skipped };
}

/** Injected source of raw acquisition rows (real: OAuth + paginated Store API; tests: a fixture). */
export interface AcquisitionSource {
  /** Fetch all acquisition rows for the given inclusive UTC date range (handles pagination). */
  fetch(startDate: string, endDate: string): Promise<MsStoreAcquisitionRow[]>;
}

export interface PullerDeps {
  source: AcquisitionSource;
  /** Write normalized rows to the destination (same table as runtime events). */
  bqInsert(rows: Ga4Row[]): void | Promise<void>;
  /** Structured progress sink (no PII). Optional. */
  log?: (msg: string) => void;
}

export interface PullResult {
  fetched: number;
  written: number;
  skipped: number;
}

/**
 * Run an acquisition pull for a date range: fetch → normalize → write. Writes nothing and reports
 * zeros when the source returns nothing (never invents data). Skipped (unplaceable) rows are
 * surfaced, not hidden.
 */
export async function runAcquisitionPull(
  startDate: string,
  endDate: string,
  deps: PullerDeps,
): Promise<PullResult> {
  const raw = await deps.source.fetch(startDate, endDate);
  const { rows, skipped } = normalizeAcquisitions(raw);
  if (rows.length > 0) await deps.bqInsert(rows);
  deps.log?.(`msstore acquisitions ${startDate}..${endDate}: fetched=${raw.length} written=${rows.length} skipped=${skipped}`);
  return { fetched: raw.length, written: rows.length, skipped };
}
