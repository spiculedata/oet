# OET — Open Event Telemetry

A platform-agnostic protocol for getting events from **any** client into BigQuery (or any warehouse).

First-party analytics SDKs (Firebase, etc.) only ship for the platforms the vendor chose — Android, iOS, Web, sometimes macOS. Everything else (Windows desktop, CLIs, Steam game builds, embedded/IoT, backend cron) is a blind spot whose events never reach your warehouse. OET closes that gap with one idea: a tiny, standard event envelope any client can POST to a single ingestion endpoint, landing **GA4-shaped** in your warehouse alongside your existing analytics.

## The envelope (`oet.event.v1`)

```
POST /ingest
{
  "client_id": "win-<guid>",     // stable per-install, generated first-run, PII-free
  "user_id": null,               // optional, only if signed in
  "platform": "windows",         // the dimension first-party SDKs can't give you
  "app_version": "2.2.0+27",
  "consent": true,               // telemetry is opt-in; respected server-side
  "events": [
    { "name": "app_open",  "ts": "...", "params": { ... } },
    { "name": "purchase",  "ts": "...", "params": { "source": "win" } }
  ],
  "sig": "hmac-sha256(...)"       // anti-abuse signature
}
```

## Two data types

1. **Runtime usage** — events the app emits itself (`app_open`, action taken). Emitter → ingestion endpoint.
2. **Acquisition** — downloads/installs/store conversions outside the app. Scheduled **pullers** hit store/analytics APIs (e.g. Microsoft Store Analytics REST API) and normalize into the same schema.

## Key design principle: be "GA4-shaped"

The destination BigQuery table mirrors GA4's `events_*` schema (`event_params`, `user_pseudo_id`, `platform`, `event_timestamp`). A single `UNION ALL` view stitches OET events together with your existing first-party export — one unified events table, existing dashboards keep working with a one-line `FROM` swap.

## Architecture (reference implementation)

- **Emitter** — ~30-line, language-agnostic lib: stable `client_id`, local buffer, POST flush with offline/retry.
- **Ingestion endpoint** — serverless: verify signature/auth → drop non-allowlisted events → stamp server timestamp + coarse geo → write to BigQuery.
- **Pullers** — scheduled functions normalizing 3rd-party acquisition data into the same table.
- **Unified view** — `UNION ALL` over first-party export + OET table.

## Security (non-negotiable — public write endpoint)

- App Check or HMAC-signed envelope (authenticity)
- Per-client rate limiting (flood protection)
- Server-side event allowlist (drop unknown names)
- PII-free enforcement + opt-in consent required

## Stack

TypeScript on Firebase/GCP Cloud Functions + BigQuery. Spec stays warehouse-agnostic; GCP is the reference target.

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit (strict)
npm run lint        # eslint (typescript-eslint)
npm test            # vitest — 184 tests green
```

Everything currently runs against **mocks / the Firebase emulator** — every real-GCP seam (Secret
Manager, Firebase Admin / App Check, the geo DB, the BigQuery client) is dependency-injected. No code
touches a live GCP project until an explicit deploy step.

### Source map

| Area | File(s) | Notes |
|---|---|---|
| Envelope contract | `src/envelope.ts` | `oet.event.v1` types + the registered `platform` set |
| Validation core | `src/validate.ts` | §2.3 field rules, batch bounds, consent gate, allowlist (pure) |
| GA4 row mapper | `src/ga4.ts` | envelope+event → GA4-shaped `events_*` row (PII-free by construction) |
| HMAC canonicalization | `src/canonical.ts` | §5.2 canonical signing payload (emitter ⇄ server agree byte-for-byte) |
| Ingestion endpoint | `src/ingest.ts`, `src/ingest-adapter.ts` | pure `handleIngest` pipeline + real-dependency adapter & HTTP wrapper |
| MS Store puller | `src/msstore-puller.ts` | acquisitions → GA4 rows (aggregate-correct, demographics never mapped) |
| Spec & schema | `docs/spec/` | `oet.event.v1.md`, `bigquery-schema.json`, `union-view.sql`, `allowlist.example.json` |

## Status — roadmap

Legend: ✅ done · 🟡 in progress · ⬜ not started. *Code-complete* = built and tested on mocks/emulator,
**not** yet deployed to a live GCP project. A reference desktop client validates the protocol end to end.

1. ✅ **Spec v0.1** (`oet.event.v1`) — envelope + event allowlist + GA4-shaped BQ schema + auth model. (`docs/spec/`)
2. ✅ **Ingestion endpoint — code-complete.** Full §7 pipeline: size-cap → HMAC/App Check (fail-closed) →
   replay-nonce → per-client/IP rate limit → opaque-202 consent gate → validate → enrich (server timestamp +
   coarse geo, raw IP never stored) → BigQuery insert. Reference BQ schema + `UNION ALL` view in `docs/spec/`.
3. 🟡 **Microsoft Store Analytics puller** — normalizer core done (aggregate acquisitions → GA4 rows). Real
   Store API / OAuth + Partner Center credentials, and scheduling, are the next slice.
4. ⬜ **Windows emitter in a reference desktop client.**
5. ⬜ **Validate against a real analytics dashboard**, then generalize for CLI / Steam / embedded.

A **spec v0.1.1** revision is queued (signed `sent_at` for replay freshness · `MAX_PARAM_VALUE_LEN` cap ·
normative aggregate-acquisition query semantics) — it is binding before the endpoint takes real traffic.

Licensed under **Apache-2.0**.
