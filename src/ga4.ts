/**
 * GA4-shaped row mapper (DOMAIN LAW 5: "GA4-shaped or it doesn't ship").
 *
 * Pure transform: a validated OET envelope + one accepted event + server-side enrichment
 * → a single warehouse row whose shape mirrors GA4's `events_*` export, exactly matching
 * `docs/spec/bigquery-schema.json` so the §8 `UNION ALL` view (union-view.sql) is
 * column-compatible with a first-party GA4 export.
 *
 * §8 field mapping:
 *   events[].name        → event_name (STRING, REQUIRED)
 *   server receive time  → event_timestamp (INT64 µs, REQUIRED) — supplied via ctx, never the client's ts
 *   events[].ts          → event_params entry {key:"client_ts", value.string_value}
 *   events[].params.*    → event_params REPEATED RECORD (key + typed value)
 *   client_id            → user_pseudo_id (STRING, REQUIRED)
 *   user_id              → user_id (STRING, NULLABLE)
 *   platform             → platform (STRING, REQUIRED)
 *   app_version          → app_info.version (RECORD)
 *   derived coarse geo   → geo.country / geo.region (RECORD) — NEVER raw IP (DOMAIN LAW 1)
 *   (constant)           → oet_ingest_version = ENVELOPE_VERSION (provenance, REQUIRED)
 *
 * This module is pure + unit-testable: the caller (the ingestion endpoint) is responsible
 * for producing the server timestamp and coarse geo and for the BigQuery streaming insert.
 */

import { ENVELOPE_VERSION } from "./envelope.js";
import type { OetEnvelope, OetEvent, ParamValue } from "./envelope.js";

/** GA4-shaped typed value sub-record; exactly one typed field is set, or the whole value is null. */
export type Ga4ParamValue =
  | { string_value: string }
  | { int_value: number }
  | { double_value: number }
  | { bool_value: boolean }
  | null;

export interface Ga4Param {
  key: string;
  value: Ga4ParamValue;
}

export interface Ga4Geo {
  country: string | null;
  region: string | null;
}

/** Server-side enrichment the endpoint supplies — kept out of the pure core so it stays testable. */
export interface EnrichmentContext {
  /** Authoritative server receive time, microseconds since epoch (GA4 `event_timestamp`). */
  eventTimestampMicros: number;
  /** Coarse geo derived from IP server-side. Raw IP is NEVER passed in or stored (DOMAIN LAW 1). */
  geo?: Ga4Geo | null;
}

/** One GA4-shaped destination row — top-level keys mirror `bigquery-schema.json`. */
export interface Ga4Row {
  event_name: string;
  event_timestamp: number;
  event_params: Ga4Param[];
  user_pseudo_id: string;
  user_id: string | null;
  platform: string;
  app_info: { version: string | null };
  geo: Ga4Geo | null;
  oet_ingest_version: string;
}

/**
 * Map one OET param value to its GA4 typed sub-record.
 *
 * Numbers: an integer that is exactly representable as a JS safe integer →
 * `int_value` (BQ INT64); anything else — a fraction OR an integer beyond
 * ±`MAX_SAFE_INTEGER` — → `double_value` (BQ FLOAT64). Routing a huge integer
 * like `1e21` to `int_value` would overflow BQ INT64 *and* JS can't represent it
 * exactly anyway, so `int_value` would be a lie (QA finding N-Q2-1).
 */
export function paramToGa4Value(v: ParamValue): Ga4ParamValue {
  if (v === null) return null;
  switch (typeof v) {
    case "string":
      return { string_value: v };
    case "boolean":
      return { bool_value: v };
    case "number":
      return Number.isSafeInteger(v) ? { int_value: v } : { double_value: v };
  }
}

/**
 * Build a GA4-shaped row from a validated envelope + one accepted event + server enrichment.
 * The client's advisory `ts` is preserved as the `client_ts` param (first), never as the
 * authoritative `event_timestamp` — that comes from `ctx` (§2.5).
 */
export function toGa4Row(
  env: OetEnvelope,
  event: OetEvent,
  ctx: EnrichmentContext,
): Ga4Row {
  const params: Ga4Param[] = [
    { key: "client_ts", value: { string_value: event.ts } },
  ];
  if (event.params) {
    for (const [key, value] of Object.entries(event.params)) {
      params.push({ key, value: paramToGa4Value(value) });
    }
  }

  const geo: Ga4Geo | null = ctx.geo
    ? { country: ctx.geo.country ?? null, region: ctx.geo.region ?? null }
    : null;

  return {
    event_name: event.name,
    event_timestamp: ctx.eventTimestampMicros,
    event_params: params,
    user_pseudo_id: env.client_id,
    user_id: env.user_id,
    platform: env.platform,
    app_info: { version: env.app_version },
    geo,
    oet_ingest_version: ENVELOPE_VERSION,
  };
}

/** Map every accepted event in an envelope to a GA4-shaped row sharing the same enrichment context. */
export function toGa4Rows(
  env: OetEnvelope,
  events: readonly OetEvent[],
  ctx: EnrichmentContext,
): Ga4Row[] {
  return events.map((e) => toGa4Row(env, e, ctx));
}
