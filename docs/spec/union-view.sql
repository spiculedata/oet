-- OET unified events view (DOMAIN LAW 5: GA4-shaped or it doesn't ship)
--
-- Stitches the OET destination table together with an existing first-party GA4 export so that
-- existing dashboards/queries keep working with a one-line FROM swap:
--     FROM `proj.analytics_123456789.events_*`   -->   FROM `proj.analytics_unified.events`
--
-- Both inputs share the GA4 events_* column shape, so the UNION ALL is column-compatible. The
-- oet_ingest_version column lets you tell the two sources apart downstream (NULL = first-party).
--
-- Replace the dataset/table identifiers below before running. Requires the OET table to match
-- bigquery-schema.json. Pullers (acquisition events) land in the SAME oet_events table, so they
-- flow through this view automatically.
--
-- ⚠️ AGGREGATE-ACQUISITION QUERY RULE (Spec v0.1.1 §8.1, LAW 5/LAW 6 — NORMATIVE):
-- Acquisition events (e.g. event_name='store_download') are AGGREGATE rows — ONE row per
-- (date, market, …) bucket, with the bucket count in event_param 'acquisition_quantity' (INT64).
-- They are NOT one row per install. Therefore:
--     Acquisition metrics MUST use SUM(acquisition_quantity), NEVER COUNT(*).
-- COUNT(*) over acquisition rows counts BUCKETS and undercounts by orders of magnitude.
-- Runtime-usage events are one-row-per-event, so COUNT(*) is correct for those.
-- (A worked SUM(acquisition_quantity) example query is in oet.event.v1.1.md §8.1 — it is kept
-- out of THIS file on purpose so the view definition has exactly the two real UNION ALL legs.)

CREATE OR REPLACE VIEW `PROJECT.analytics_unified.events` AS

-- First-party GA4 export (the columns OET mirrors). Add more GA4 columns to BOTH legs as needed.
SELECT
  event_name,
  event_timestamp,
  event_params,
  user_pseudo_id,
  user_id,
  platform,
  app_info,
  geo,
  CAST(NULL AS STRING) AS oet_ingest_version   -- first-party rows have no OET provenance
FROM `PROJECT.analytics_123456789.events_*`

UNION ALL

-- OET events (runtime usage + acquisition pullers), already GA4-shaped.
SELECT
  event_name,
  event_timestamp,
  event_params,
  user_pseudo_id,
  user_id,
  platform,
  app_info,
  geo,
  oet_ingest_version
FROM `PROJECT.oet.oet_events`;
