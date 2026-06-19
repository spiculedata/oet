# OET Spec v0.1 — `oet.event.v1`

> **➡️ Superseded by [`oet.event.v1.1`](./oet.event.v1.1.md)** (additive). v0.1.1 adds a signed `sent_at`
> field (replay freshness, §5.5), a `MAX_PARAM_VALUE_LEN` cap (§2.3), and normative aggregate-acquisition
> query semantics (§8.1). This v0.1 document remains the base contract — read it first, then v0.1.1 for the deltas.

**Status:** Ratified base (v0.1), extended by v0.1.1 · **Author:** Maximus (LEAD) · **M1 gates:** SEC ✅ + QA ✅

Open Event Telemetry is a platform-agnostic protocol for getting events from **any** client into a
warehouse. This document specifies the wire envelope, the server-side processing contract, the
GA4-shaped destination schema, and the authentication / anti-abuse model. The reference target is
Google Cloud (Cloud Functions + BigQuery); the protocol itself is warehouse-agnostic.

This spec is **normative**. The words MUST, MUST NOT, SHOULD, and MAY are used in the RFC-2119 sense.

---

## 1. Scope & vocabulary

| Term | Meaning |
|---|---|
| **Emitter** | Client-side code that builds and POSTs envelopes (runtime usage). |
| **Puller** | Scheduled server-side job that fetches acquisition data from a 3rd-party API and emits the same schema. |
| **Ingestion endpoint** | The single serverless function that receives `POST /ingest`. |
| **Envelope** | One `oet.event.v1` JSON request body carrying a batch of events. |
| **Destination** | The GA4-shaped warehouse table OET writes to. |
| **Allowlist** | The server-side set of permitted event names; unknown names are dropped. |

Two data types are in scope:

1. **Runtime usage** — events the app emits itself (`app_open`, an action taken). Emitter → endpoint.
2. **Acquisition** — downloads / installs / store conversions that happen *outside* the app. Puller →
   same destination schema (e.g. Microsoft Store Analytics REST API).

---

## 2. The envelope (`oet.event.v1`)

### 2.1 Transport

- `POST /ingest`
- `Content-Type: application/json; charset=utf-8`
- Body MUST be a single JSON object conforming to §2.2.
- The server MUST reject bodies larger than **256 KiB** (`413`) and batches of more than **1000**
  events (`413`). These bound per-request cost (DOMAIN LAW 4).

### 2.2 Schema

```jsonc
{
  "client_id":  "win-3f2a9c7e",   // REQUIRED. Stable-per-install, vendor-free GUID. PII-free.
  "user_id":    null,             // REQUIRED key; value null unless a user is signed in.
  "platform":   "windows",        // REQUIRED. Lowercase token; see §2.4.
  "app_version":"2.2.0+27",       // REQUIRED. Free-form version string (semver+build recommended).
  "consent":    true,             // REQUIRED. Opt-in; false/absent ⇒ nothing is retained (§4.2).
  "events": [                     // REQUIRED. 1..1000 events.
    {
      "name":   "app_open",       // REQUIRED. Must be on the allowlist (§3) or it is dropped.
      "ts":     "2026-06-18T12:00:00.000Z", // REQUIRED. Client ISO-8601 UTC. Advisory only (§2.5).
      "params": { "source": "win" }         // OPTIONAL. Flat map; values string|number|boolean|null.
    }
  ],
  "sig": "hmac-sha256:base64..."  // REQUIRED unless App Check is used instead (§5).
}
```

### 2.3 Field rules

| Field | Type | Rule |
|---|---|---|
| `client_id` | string | 1–128 chars, `[A-Za-z0-9._-]`. Stable per install, generated first-run. MUST NOT encode PII (no email/username/hardware serial). Convention: `<platform>-<guid>`. |
| `user_id` | string \| null | Present as a key always. Non-null only when the user is authenticated in the host app. MUST NOT be an email or raw account name — use an opaque app-side id. |
| `platform` | string | Lowercase token from §2.4 (or a new registered token). |
| `app_version` | string | ≤64 chars. Opaque to OET. |
| `consent` | boolean | MUST be exactly `true` for retention. Any other value ⇒ drop all (§4.2). |
| `events[].name` | string | ≤64 chars, `snake_case`, `[a-z][a-z0-9_]*`. Allowlist-checked (§3). |
| `events[].ts` | string | ISO-8601 with timezone. Advisory; server stamps authoritative time (§2.5). |
| `events[].params` | object | ≤25 keys; keys ≤40 chars `snake_case`; values `string\|number\|boolean\|null`. No nested objects/arrays in v1. Param values MUST be PII-free. |
| `sig` | string | `hmac-sha256:<base64>` over the canonical payload (§5.2). REQUIRED unless §5.3 App Check. |

### 2.4 Registered `platform` tokens (v0.1)

`android` · `ios` · `web` · `macos` · `windows` · `linux` · `steam` · `cli` · `embedded` · `server`.
New tokens MAY be added by spec revision; clients MUST NOT invent ad-hoc casing variants.

### 2.5 Timestamps

Clients send `ts` (advisory — clocks drift, and a public field is forgeable). The server MUST stamp an
authoritative **`event_timestamp`** at receive time (microseconds since epoch, GA4-shaped). Downstream
queries SHOULD treat the server timestamp as canonical and `ts` (mapped to an event param) as a hint.

---

## 3. Event allowlist (server-side)

- The server holds an **allowlist** of permitted `events[].name` values (config, not client input).
- For each event: if `name ∈ allowlist` → accept; else → **drop and count** (`event_not_allowlisted`).
  Dropped events MUST NOT be written to the destination (metric-poison guard, DOMAIN LAW 3).
- An envelope where *every* event is dropped is processed as "nothing to write" — the request still
  returns `202` (see §6) so a misconfigured client can't distinguish allow/deny and probe the list.
- The allowlist is per-deployment. A starter list ships in code (`DEFAULT_ALLOWLIST`); production
  deployments SHOULD source it from config. See `allowlist.example.json`.

---

## 4. Consent & PII (DOMAIN LAWS 1–2, 8)

### 4.1 PII-free

The envelope, the destination, and all logs MUST be free of personal data: no emails, names, raw IP
addresses, phone numbers, precise geolocation, or hardware fingerprints. `client_id` is a random
per-install GUID; `user_id` is an opaque app id. Coarse geo (country/region from IP) MAY be derived
server-side and stored, but the **raw IP MUST NOT be stored or logged**.

### 4.2 Opt-in consent

Telemetry is opt-in. The server MUST verify `consent === true` **server-side** before retaining
anything; a client claiming consent it didn't collect is the client's compliance burden, but the
server never relies on client UI state beyond this flag. `consent !== true` ⇒ the entire envelope is
discarded (no partial retention), returning `202` (§6).

---

## 5. Authentication & anti-abuse (DOMAIN LAW 4)

`/ingest` is a **public write endpoint** → the threat model is **metric poisoning** and **cost
inflation**. Two authenticity modes are defined; a deployment MUST enable at least one.

### 5.1 Modes

| Mode | Use when | Mechanism |
|---|---|---|
| **HMAC** (§5.2) | Native/desktop/CLI/embedded clients, pullers | Shared per-app secret signs the payload. |
| **App Check** (§5.3) | Firebase-attached clients | Platform attestation token verified server-side. |

### 5.2 HMAC signature

- `sig = "hmac-sha256:" + base64( HMAC-SHA256( key = app_secret, msg = canonical(envelope) ) )`.
- **Canonical payload** = the UTF-8 JSON of the envelope **with the `sig` field removed**, keys sorted
  lexicographically at every level, no insignificant whitespace. (A canonicalization helper ships in the
  reference impl so emitter and server agree byte-for-byte.)
- The server recomputes and compares in **constant time**. Mismatch ⇒ `401`.
- The `app_secret` is per-app, provisioned out-of-band, stored server-side only. It MUST NOT ship in
  client source in plaintext where avoidable; for fully untrusted clients prefer App Check.
  *(Open SEC question — see §9: HMAC in a shipped desktop binary is extractable; SEC to rule on
  acceptable mitigations: short-lived keys, per-install keys, App Check fallback.)*
- **Replay:** the server SHOULD reject envelopes whose authoritative receive time is implausibly far
  from now and MAY maintain a short-window nonce/seen-cache. v0.1 leaves the exact replay window to SEC.

### 5.3 App Check

For Firebase clients, the client attaches an App Check token; the server verifies it via the Firebase
Admin SDK before processing. When App Check passes, `sig` MAY be omitted.

### 5.4 Rate limiting

The server MUST rate-limit per `client_id` **and** per source IP (token-bucket or fixed-window).
Defaults (tunable, SEC to ratify): **60 requests / 5 min per client_id**, **600 / 5 min per IP**.
Over-limit ⇒ `429` with `Retry-After`. Limits fail **closed** under backing-store outage only for
*unauthenticated* traffic; authenticated traffic SHOULD fail open to avoid dropping real data — SEC
to ratify this trade-off.

---

## 6. Server response contract

| Status | Meaning |
|---|---|
| `202 Accepted` | Envelope received and processed (incl. "all dropped" / "no consent" — opaque by design §3). |
| `400 Bad Request` | Malformed JSON or envelope shape (§2.2). |
| `401 Unauthorized` | Signature/App Check failed (§5). |
| `413 Payload Too Large` | Body > 256 KiB or > 1000 events (§2.1). |
| `429 Too Many Requests` | Rate limit exceeded (§5.4); includes `Retry-After`. |

Responses MUST NOT leak whether a specific event name is allowlisted, whether a `client_id` is known,
or internal error detail. Bodies are minimal (`{"ok":true}` / `{"error":"<code>"}`).

---

## 7. Processing pipeline (normative order)

```
receive → size/shape check (400/413)
        → authenticity: HMAC or App Check (401)
        → rate limit per client_id + IP (429)
        → consent check: consent===true else drop-all (202)
        → allowlist filter: keep known event names (drop+count others)
        → enrich: stamp event_timestamp (server), derive coarse geo (drop raw IP)
        → write accepted events to destination (GA4-shaped rows)
        → 202
```

The pure, unit-testable core (shape + consent + allowlist) lives in `src/validate.ts`. Authenticity,
rate limiting, enrichment, and the warehouse write are the endpoint's responsibility (milestone 2).

---

## 8. Destination: GA4-shaped warehouse (DOMAIN LAW 5)

The destination table mirrors GA4's `events_*` export so a single `UNION ALL` view stitches OET rows
together with an existing first-party GA4 export — existing dashboards keep working with a one-line
`FROM` swap. The BigQuery schema is specified in **`bigquery-schema.json`**; the union pattern in
**`union-view.sql`**. Field mapping summary:

| OET envelope | GA4-shaped column |
|---|---|
| `events[].name` | `event_name` (STRING) |
| server receive time | `event_timestamp` (INT64, µs since epoch) |
| `events[].ts` | `event_params` entry `{key:"client_ts", value.string_value:...}` |
| `events[].params.*` | `event_params` REPEATED RECORD (`key` + typed `value`) |
| `client_id` | `user_pseudo_id` (STRING) |
| `user_id` | `user_id` (STRING, nullable) |
| `platform` | `platform` (STRING) |
| `app_version` | `app_info.version` (RECORD) |
| derived coarse geo | `geo.country`, `geo.region` (RECORD) — never raw IP |
| — | `oet_ingest_version` = `"oet.event.v1"` (provenance, STRING) |

Provenance (`oet_ingest_version`) is stamped on every row so OET-sourced data is always
distinguishable from first-party export downstream.

---

## 9. Open questions for the SEC gate

1. **HMAC key distribution** for shipped untrusted binaries (extractable secret). Per-install keys?
   Short-lived keys via a provisioning call? App Check-only for desktop?
2. **Replay window** + whether a nonce cache is in-scope for v0.1.
3. **Rate-limit fail-open vs fail-closed** split for authenticated vs unauthenticated traffic (§5.4).
4. **Coarse-geo granularity** — country only, or country+region? Region may approach PII in low-pop areas.
5. **Puller authenticity** — pullers run server-side; do they bypass HMAC and use the writer's IAM only?

## 10. Open questions for the QA gate

1. Contract test vectors for §2.2 (valid + every rejection class) — canonical fixtures.
2. GA4-shape conformance assertions against `bigquery-schema.json` (column names/types/modes).
3. `UNION ALL` view: a test that OET rows and a mock first-party export co-query without type errors.
4. HMAC canonicalization: cross-check emitter-side and server-side produce identical signatures.

---

*v0.1 is the contract for milestones 2–5. Changes after SEC/QA gating bump to `oet.event.v1.1` (additive)
or `oet.event.v2` (breaking). The version travels on every row via `oet_ingest_version`.*
