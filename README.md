# OET — Open Event Telemetry

A platform-agnostic protocol for getting events from **any** client into BigQuery (or any warehouse).

First-party analytics SDKs (Firebase, etc.) only ship for the platforms the vendor chose — Android, iOS, Web, sometimes macOS. Everything else (Windows desktop, CLIs, Steam game builds, embedded/IoT, backend cron) is a blind spot whose events never reach your warehouse. OET closes that gap with one idea: a tiny, standard event envelope any client can POST to a single ingestion endpoint, landing **GA4-shaped** in your warehouse alongside your existing analytics.

## The envelope (`oet.event.v1.1`)

```
POST /ingest
{
  "client_id": "win-<guid>",     // stable per-install, generated first-run, PII-free
  "user_id": null,               // optional, only if signed in (never an email/raw account)
  "platform": "windows",         // the dimension first-party SDKs can't give you
  "app_version": "2.2.0+27",
  "consent": true,               // telemetry is opt-in; respected server-side
  "sent_at": "2026-06-19T12:00:00Z", // when THIS batch was flushed — signed, replay-freshness anchor
  "events": [
    { "name": "app_open",  "ts": "...", "params": { ... } },
    { "name": "purchase",  "ts": "...", "params": { "source": "win" } }
  ],
  "sig": "hmac-sha256(...)"       // HMAC over the canonical envelope (anti-abuse / authenticity)
}
```

The current contract is **`oet.event.v1.1`** (`docs/spec/oet.event.v1.1.md`) — additive over v0.1: it adds
the signed `sent_at` field, a `MAX_PARAM_VALUE_LEN` cap, and normative aggregate-acquisition query semantics.

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

- **Authenticity** — HMAC-signed envelope (constant-time compare) or App Check; fail-closed.
- **Replay protection** — signed `sent_at` freshness window (asymmetric −5m/+1m) + an **atomic** nonce
  `claim` (no check-then-write race), with a **shared store (Firestore) so replay/limits hold across instances**.
- **Flood protection** — a pre-auth per-IP gate (sheds before any crypto is spent) + per-client/per-IP rate limits.
- **Server-side event allowlist** — unknown event names are dropped, never written (metric-poison guard).
- **PII-free enforcement + opt-in consent** — no client_id/user_id/IP/secrets in logs; consent verified server-side;
  security events are emitted as coarse categories only.

The reference endpoint passed an independent security audit before being considered public-traffic-ready;
remaining gates (App Check wiring, per-install keys, coarse-geo, a first-authenticated smoke) are deploy-time.

## Stack

TypeScript on Firebase/GCP Cloud Functions + BigQuery. Spec stays warehouse-agnostic; GCP is the reference target.

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit (strict)
npm run lint        # eslint (typescript-eslint)
npm test            # vitest — 255 tests green
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
| Replay/limit shared store | `src/ingest-store.ts`, `functions/src/firestore-store.ts` | cross-instance atomic nonce + rate counter (in-mem iface; Firestore impl) |
| Reference emitter | `src/emitter.ts`, `src/emitter-adapter.ts` | stable `client_id`, buffer, signed flush w/ retry; fetch transport + persistent id store |
| MS Store puller | `src/msstore-puller.ts` | acquisitions → GA4 rows (aggregate-correct, demographics never mapped) |
| Deploy (Step-1 artifacts) | `functions/`, `firebase.json`, `deploy/` | Cloud Function wrapper, `oet-telemetry` placeholder project, local smoke + runbook |
| Spec & schema | `docs/spec/` | `oet.event.v1.md` + **`oet.event.v1.1.md`**, `bigquery-schema.json`, `union-view.sql`, `allowlist.example.json` |

## Status — roadmap

Legend: ✅ done · 🟡 in progress · ⬜ not started. *Code-complete* = built and tested on mocks/the Firebase
emulator, **not** yet deployed to a live GCP project.

1. ✅ **Spec v0.1 + v0.1.1** — envelope, event allowlist, GA4-shaped BQ schema, auth/replay model, signed
   `sent_at`, `MAX_PARAM_VALUE_LEN`, aggregate-acquisition query semantics. (`docs/spec/`)
2. ✅ **Ingestion endpoint — code-complete + hardened.** Full pipeline: pre-auth IP gate → size-cap →
   HMAC/App Check (fail-closed) → freshness + atomic replay-nonce → per-client/IP rate limit (shared store,
   correct across instances) → opaque-202 consent gate → validate → enrich (server timestamp + coarse geo,
   raw IP never stored) → BigQuery insert. PII-free structured security events. Passed an independent security
   audit; production-scale-ready in code.
3. ✅ **Reference emitter** — stable `client_id`, local buffer, signed flush with offline/retry.
4. 🟡 **Microsoft Store Analytics puller** — normalizer core done (aggregate acquisitions → GA4 rows). Real
   Store API / OAuth + credentials and scheduling are the next slice.
5. ⬜ **Deploy** (Step-1 artifacts ready: Cloud Function wrapper, smoke test, runbook) → ⬜ **integrate into a
   real client** → ⬜ **validate against a real analytics dashboard**, then generalize for CLI / Steam / embedded.

Everything above is verified on mocks/emulator; the live deploy + real-client integration are the remaining
work. Licensed under **Apache-2.0**.
