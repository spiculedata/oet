# Data-subject erasure (A6 — audit #2)

A runnable erasure procedure for a data-subject deletion request against the OET events table
(`<project>.oet.oet_events`). OET is PII-free by design (no raw IP, opt-in consent, coarse geo), so the
only subject identifiers in a row are:

| Column | Source | Notes |
|---|---|---|
| `user_pseudo_id` (STRING, REQUIRED) | the envelope `client_id` | a per-install pseudonymous id |
| `user_id` (STRING, NULLABLE) | the envelope `user_id` | present only if the client set one |

## Erasure query
Delete every event for a subject. Run with the **exact** id(s) the requester is identified by; prefer
`user_id` when known, else the install's `user_pseudo_id` (`client_id`):

```sql
-- by application user id (when the client sent user_id)
DELETE FROM `PROJECT.oet.oet_events`
WHERE user_id = @user_id;

-- by install pseudo id (the client_id) — covers consent-less installs that never set user_id
DELETE FROM `PROJECT.oet.oet_events`
WHERE user_pseudo_id = @user_pseudo_id;
```

Run via `bq`:
```
bq query --use_legacy_sql=false \
  --parameter='user_id:STRING:<the-user-id>' \
  'DELETE FROM `oet-telemetry.oet.oet_events` WHERE user_id = @user_id'
```

**Verify** nothing remains:
```sql
SELECT COUNT(*) AS remaining
FROM `PROJECT.oet.oet_events`
WHERE user_id = @user_id OR user_pseudo_id = @user_pseudo_id;
-- expect 0
```

## Notes
- BigQuery DML on a streaming table: rows in the **streaming buffer** (recently inserted, typically
  < ~90 min old) can't be deleted by DML until they flush to managed storage — re-run after the buffer
  flushes if a fresh row survives.
- If per-install **keys** are in use (GL3), also revoke the install's secret so it can't write again:
  `gcloud secrets delete oet-client-<client_id>` (the `client_id` == `user_pseudo_id`).
- **Residency** (which region/dataset location data lives in) is an **Owner/DEVOPS** decision at dataset
  creation (`deploy/bq-setup.sh` location), not a code control — out of scope here.
- This is a manual operator runbook. An automated erasure endpoint/queue is a future item if request
  volume warrants it.
