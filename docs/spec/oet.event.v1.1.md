# OET Spec v0.1.1 — `oet.event.v1.1` (additive revision)

**Status:** Draft · **Author:** Maximus (LEAD/steward) · **Gates:** ⬜ SEC ⬜ QA (pending)
**Supersedes:** [`oet.event.v1`](./oet.event.v1.md) · **Compatibility:** additive — see §0.

This revision closes three items the M1–M4 gates raised and routed to the spec steward:

1. **`sent_at`** — a signed top-level transmission timestamp that gives replay protection a *freshness*
   anchor (closes SEC **C8** / DEV **SP1** / QA **F-RETRY**).
2. **`MAX_PARAM_VALUE_LEN`** — a per-param-value length cap (closes SEC **N1**).
3. **Aggregate-acquisition query semantics** — makes the "`SUM(acquisition_quantity)`, never `COUNT(*)`"
   rule normative (the LAW 5/LAW 6 consequence SEC ruled at the M3 gate).

Normative language is RFC-2119. Section numbers below extend [`oet.event.v1`](./oet.event.v1.md); anything
not restated here is unchanged from v0.1.

---

## 0. Versioning & compatibility

- The wire envelope gains **one new REQUIRED field, `sent_at`** (§5.5). This is the only structural change.
- **Provenance:** rows ingested under this revision stamp `oet_ingest_version = "oet.event.v1.1"` (the v0.1
  field-shape is otherwise identical, so the GA4 schema and `UNION ALL` view are **unchanged** — no table
  migration). A deployment MAY accept both `oet.event.v1` and `oet.event.v1.1` envelopes during transition.
- **Why this can be REQUIRED rather than optional:** OET has **no production clients yet** (everything is
  mock/emulator pre-deploy), so v0.1.1 supersedes v0.1 *before* first real traffic. The reference emitter is
  updated in lockstep. The §5.4 replay-*freshness* enforcement (asymmetric −`FUTURE_SKEW`/+`PAST_WINDOW`,
  nonce anchored to `sent_at + PAST_WINDOW`) is **binding before the endpoint takes real traffic under the
  Owner's deploy GO** (it was always going to be — this revision is what makes it checkable).

---

## 5.5 `sent_at` — signed transmission timestamp (closes C8 / SP1 / F-RETRY)

### Problem (from the gates)

v0.1 defends replay with a server-side **nonce cache** keyed on `sig`. That blocks a replayed envelope only
*while its nonce is still cached* (bounded by the cache TTL). After the window, the same captured envelope
can be resent and there is nothing canonical to reject it on:

- event `ts` **cannot** serve as the freshness anchor — for offline/batched clients an event is *legitimately*
  hours or days old, so a stale `ts` is normal, not suspicious;
- a freshness check on the *unsigned* receive metadata is trivially forgeable.

There is also the dual failure (**F-RETRY**): a genuine client retry of a request that the server already
processed but whose response was lost is **indistinguishable from a replay** without a transmission time.

### Definition

Add one REQUIRED top-level envelope field:

```jsonc
{
  "client_id": "...",
  ...
  "sent_at": "2026-06-18T12:00:00.000Z",   // REQUIRED. ISO-8601 UTC, when THIS envelope was flushed.
  "events": [ ... ],
  "sig": "hmac-sha256:..."
}
```

| Field | Type | Rule |
|---|---|---|
| `sent_at` | string | ISO-8601 with timezone (Z or ±hh:mm). The wall-clock time the client **assembled/flushed this envelope**, NOT any event's `ts`. Set once per flush. On a retry of the *same* buffered batch, the client SHOULD keep the original `sent_at` (so a retry stays within the window; see §5.4). |

`sent_at` **MUST be inside the canonical signing payload** (§5.2) — it is covered by `sig`, so it cannot be
altered in transit. (No separate field handling is needed: §5.2 already signs the whole envelope minus `sig`,
so adding `sent_at` to the envelope automatically signs it. Emitter and server canonicalizers gain the field
for free.)

### 5.4 (amended) — rate limiting **and replay**

Replace v0.1 §5.4's replay paragraph with the two-part check, evaluated **after** signature verification.

The freshness window is **asymmetric** (SEC S3): transit and modest client lag only ever make a real envelope
look *older*, so a `sent_at` in the **future** is the dangerous, attacker-leaning direction and gets a tight
bound. Two server-side bounds (single global pair, **deployment-tunable but NEVER per-platform** — platform is
attacker-chosen, so a per-platform window lets an attacker select the loosest; SEC S1):

- **`PAST_WINDOW` = 5 minutes** (default) — how far in the past `sent_at` may be vs. receive time.
- **`FUTURE_SKEW` = 1 minute** (default) — how far in the future `sent_at` may be vs. receive time.

1. **Freshness.** Let `Δ = server_receive_time − sent_at`. Reject `401` unless
   `−FUTURE_SKEW ≤ Δ ≤ PAST_WINDOW` (too old **or** too-far-future ⇒ `401`).
2. **Nonce.** Within the fresh band, the `sig`-nonce cache rejects duplicates (`seen ⇒ 401`, else record).
   **The nonce expiry MUST be anchored to `sent_at + PAST_WINDOW`, not to receive time** (SEC S2). A fresh copy
   of a given envelope can legitimately arrive as late as `sent_at + PAST_WINDOW`, so the nonce must be retained
   until exactly then — anchoring to receive time would evict the nonce early when the client clock runs ahead
   (`sent_at` future by δ), opening a δ-long window where a replay is fresh but un-noticed. Anchoring to
   `sent_at + PAST_WINDOW` makes nonce coverage **exactly** match the freshness band (no gap) while keeping
   memory bounded (a nonce lives ≤ `PAST_WINDOW + FUTURE_SKEW` past receive).

Net: a captured envelope is accepted at most **once**, and only within its asymmetric fresh band — after that
it fails freshness; inside it, the nonce. No clock-ahead gap.

> **Non-normative impl guidance (SEC S-RESIDUAL):** the endpoint SHOULD record the nonce **after** a successful
> BigQuery write, not before. Because every row already carries a deterministic `insertId` (BQ dedups concurrent
> retries), recording the nonce post-write makes a retry-after-*total-write-failure* lossless instead of a
> nonce-blocked `401` with no data landed. This is an endpoint-slice refinement, not a wire-contract rule.

### F-RETRY guidance (non-normative)

A legitimate retry keeps the **same `sent_at` and same `sig`** → the server's nonce cache recognizes it as a
duplicate and returns `401`. To make a lost-response retry *safe* (not silently dropped), clients SHOULD rely
on the endpoint's **idempotent BigQuery write** (deterministic `insertId` per row, already specified for the
adapter): re-POSTing the identical batch within the window is deduped at the warehouse, so "retry → 401 at the
endpoint but the data already landed" is the *correct, lossless* outcome. Clients MUST NOT mint a fresh
`sent_at`/`sig` to force a retry through — that would double-write. (A future v0.2 MAY add an explicit
idempotency key if retry-after-window becomes a real need.)

### Clock skew

Clients SHOULD sync to a reliable clock. A client whose clock is **behind** by more than `PAST_WINDOW`, or
**ahead** by more than `FUTURE_SKEW`, is rejected `401` — intended (an unbounded-skew allowance would reopen
the replay hole). The asymmetry is deliberate: a fast (future) clock is the riskier case, so its tolerance is
tighter. Deployments MAY widen the bounds for fleets with known-poor clocks, accepting the proportionally
larger replay band — but SHOULD keep `FUTURE_SKEW` as small as the fleet allows.

---

## 2.3 (amended) — `MAX_PARAM_VALUE_LEN` param-value cap (closes N1)

v0.1 §2.3 caps the param **count** (≤25) and param **key** length (≤40), but not the **value** length. A
single event could carry several near-`MAX_BODY` string values — wasteful storage and a low-grade abuse vector.

Add to the per-event field rules:

- A **string** param value MUST be ≤ **`MAX_PARAM_VALUE_LEN = 1024`** characters (UTF-16 code units, matching
  JS `String.length`). Number / boolean / null values are unaffected.
- Violation is handled like the other §2.3 per-event rules: **drop + count** the offending event with reason
  `event_invalid:<name>:param_value_length` (→ still `202`, one bad event never sinks the batch).

`MAX_PARAM_VALUE_LEN` joins the single-source-of-truth limit constants alongside `MAX_PARAM_KEYS`,
`MAX_EVENT_NAME_LEN`, etc.

---

## 8.1 (new) — Aggregate-acquisition query semantics (LAW 5 / LAW 6, normative)

Acquisition pullers (e.g. the MS Store puller) normalize **aggregate** source data: the upstream API returns
counts per (date, market, …) bucket, not per-user events. Per LAW 6 (never fabricate data), OET emits **one
row per bucket** carrying the bucket count in the event param **`acquisition_quantity`** (INT64) — it does
**not** explode an aggregate of N into N synthetic per-user rows.

This is the single-table/`UNION ALL` design (LAW 5) working as intended, but it imposes a **normative query
rule** on every consumer of acquisition events:

> **Acquisition metrics MUST be computed as `SUM(acquisition_quantity)`, NEVER `COUNT(*)`.**
> `COUNT(*)` over acquisition rows counts *buckets*, not acquisitions, and will undercount by orders of
> magnitude. Runtime-usage events are unaffected (they are one row per event, so `COUNT(*)` is correct there).

Acquisition rows are self-identifying — they carry `acquisition_quantity` and an `oet_*` source param and an
aggregate `user_pseudo_id` prefix (e.g. `msstore-agg:`) — so a query can always tell the two row classes apart:

```sql
-- Windows downloads in a period (CORRECT):
SELECT SUM(
  (SELECT value.int_value FROM UNNEST(event_params) WHERE key = 'acquisition_quantity')
) AS windows_downloads
FROM `PROJECT.analytics_unified.events`
WHERE event_name = 'store_download' AND platform = 'windows'
  AND event_timestamp BETWEEN @start AND @end;
-- COUNT(*) here would return the number of (day×market) buckets — WRONG.
```

`event_name` stays **`store_download`** (an acquisition, not an install). The `union-view.sql` companion
carries this rule as an inline comment so it is visible at the point of use. QA asserts the convention at M5.

---

## Changes to companion artifacts

- `union-view.sql` — gains a header comment stating the `SUM(acquisition_quantity)` rule + the example query.
- `bigquery-schema.json` — **unchanged** (v0.1.1 stores no new columns; `sent_at` is transport metadata used
  for the freshness check and is **not** persisted by default — it MAY be recorded as an `event_params` entry
  `client_sent_at` for debugging, which fits the existing schema).
- Reference emitter / endpoint — DEV adds `sent_at` to the envelope it builds and signs, and the endpoint adds
  the §5.4 freshness check; `MAX_PARAM_VALUE_LEN` joins `validate.ts`. (Implementation slices, gated separately.)

---

## Open questions for the gates

**SEC — RESOLVED at the SEC gate (folded into §5.4 above):** (S1) ✅ one global server-side window, **never
per-platform** (attacker picks the loosest). (S2) ✅ nonce expiry anchored to **`sent_at + PAST_WINDOW`**, not
receive — closes the clock-ahead gap. (S3) ✅ **asymmetric** window (past −5 min / future +1 min) — a future
`sent_at` is the dangerous direction. (S-RESIDUAL, non-blocking) record the nonce *after* a successful BQ
write so retry-after-write-failure is lossless — captured as endpoint-slice impl guidance in §5.4.

**QA:** (Q1') Contract vectors for `sent_at`: missing→400, stale/future→401, valid-in-window→202, and the
freshness+nonce interaction. (Q2') `param_value_length` drop+count vector at the 1024 boundary. (Q3') A query
test asserting `SUM(acquisition_quantity)` vs the wrong `COUNT(*)` on a mixed runtime+acquisition fixture.
