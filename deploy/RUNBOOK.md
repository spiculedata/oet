# OET — GCP deploy runbook (Cloud Functions + BigQuery)

Target project: **`oet-telemetry`** — a **standalone OET GCP project** (OET is a vendor-neutral protocol;
it is NOT co-tenanted in any app's project). **The project already exists** (created empty, no billing yet);
`.firebaserc` points at it. Endpoint deploys as the isolated **`oet`** functions codebase; data lands in the
dedicated **`oet.oet_events`** BigQuery dataset; rate-limit + replay state live in **Firestore** (`oet_nonces`
/ `oet_counters`) so the function is correct across instances.

> **Locked-down by design.** The function deploys `invoker: "private"` — only IAM-authenticated callers,
> NOT the public internet. It is opened to unauthenticated public traffic ONLY after the **C8/SP1
> signed-`sent_at` replay-freshness** defense lands (SEC's binding pre-traffic condition) and AD1 (a
> platform ingress request-size cap) is confirmed. Until then this is a validated-but-private endpoint.

---

## Step 1 — PROVEN LOCALLY (no GCP, no money) ✅
The exact endpoint logic that deploys is proven over real HTTP with a logging BigQuery mock:

```bash
npm run build
node deploy/smoke.mjs      # emitter → endpoint → (logged) BQ; HMAC 401, consent-202, allowlist-drop
```

## Step 2 — real deploy (needs Owner GO + auth; spends money)

1. **Authenticate** (interactive — run these yourself):
   ```
   gcloud auth login
   firebase login
   gcloud config set project oet-telemetry
   ```
2. **Link billing + enable APIs** (Cloud Functions gen2, BigQuery, Firestore are billed):
   ```
   gcloud billing projects link oet-telemetry --billing-account=<YOUR_BILLING_ACCOUNT>
   gcloud services enable cloudfunctions cloudbuild run artifactregistry eventarc \
     bigquery secretmanager firestore logging pubsub --project=oet-telemetry
   ```
3. **Create the BigQuery dataset + table** (idempotent):
   ```
   bash deploy/bq-setup.sh oet-telemetry US
   ```
3b. **Create the Firestore database + TTL policies** (shared rate-limit/replay store):
   ```
   gcloud firestore databases create --location=nam5 --project=oet-telemetry   # once
   # TTL policies so expired nonce/counter docs self-delete (correctness is in-txn; TTL reclaims storage):
   gcloud firestore fields ttls update expiresAt --collection-group=oet_nonces   --enable-ttl --project=oet-telemetry
   gcloud firestore fields ttls update expiresAt --collection-group=oet_counters --enable-ttl --project=oet-telemetry
   ```
4. **Set the HMAC secret** (per-app shared secret the emitter signs with; never in source):
   ```
   firebase functions:secrets:set OET_HMAC_SECRET     # paste a strong random value
   ```
5. **Deploy the function (locked-down)**:
   ```
   firebase deploy --only functions:oet
   ```
   The function is created with `invoker: private`. Confirm it is NOT publicly invokable:
   ```
   gcloud functions describe ingest --region us-central1 --gen2 \
     --format="value(serviceConfig.uri)"
   # calling without an identity token should return 401/403
   ```
6. **Smoke the deployed (private) endpoint** with an authenticated call:
   ```
   TOKEN=$(gcloud auth print-identity-token)
   curl -s -X POST "<function-uri>" -H "Authorization: Bearer $TOKEN" \
        -H "content-type: application/json" --data @sample-signed-envelope.json
   # expect 202; verify a row in oet-telemetry:oet.oet_events
   ```

## Step 3 — open to public traffic (LATER, gated)
Do NOT do this until:
- **C8/SP1** signed `sent_at` replay-freshness is implemented + gated (spec v0.1.1), and
- **AD1** ingress request-size cap is enforced at the platform edge, and
- a coarse-geo provider (country-only, EC1) is wired (until then `geo` is null — gaps stay gaps).

Then grant public invoke:
```
gcloud functions add-invoker-policy-binding ingest --region us-central1 \
  --member="allUsers"
```

## Rollback
```
firebase functions:delete oet:ingest --region us-central1
# (BigQuery dataset/table persist; delete with `bq rm -r -d oet-telemetry:oet` if desired)
```

## Notes / gaps (honest)
- **Geo (GL2)**: country-only geo is derived from a **trusted edge header** — set `OET_COUNTRY_HEADER` to the
  header your LB/Cloud Armor injects (e.g. the Cloud CDN/Armor geo header). Raw IP is never used for geo (it
  stays at the edge). Unset ⇒ `geo` is null (gaps stay gaps). Region stays off (k-anon).
- **App Check (GL2)**: real `firebase-admin` `getAppCheck().verifyToken` is wired but **OFF by default**. Once
  App Check is configured in the Firebase project, set `OET_APP_CHECK_ENABLED=true` to verify the
  `x-firebase-appcheck` header (fail-closed). While off, a stray App-Check header is ignored and HMAC runs (F10).
- **Rate limiter / replay cache** are now backed by the **shared Firestore store** (`functions/src/firestore-store.ts`)
  — atomic `claim`/transaction, correct + race-free across instances (D-STORE / D-STORE-CAS), so the function
  runs at `maxInstances: 10`. Needs the Firestore database + TTL policies from step 3b.
- **Secret distribution**: `OET_HMAC_SECRET` is a single shared secret. Per SEC ruling #1 / C9, a shipped
  untrusted client must NOT embed a global secret — turn on **per-install keys** (`OET_PER_INSTALL_KEYS=1`,
  GL3 — see below) or App Check before any real client ships with it.

## MS Store acquisitions puller (GL1) — daily scheduled function
Deploys as `msstoreAcquisitionsPull` (Cloud Scheduler → Pub/Sub, daily 03:00 UTC) alongside `ingest`. It
no-ops until the Owner supplies the Azure AD app registration + Store product id:
1. **Azure AD app registration** (Partner Center / Entra): an app with access to the Store Analytics API.
   Note its **tenant id** + **client id**; create a **client secret**.
2. **Store the OAuth secret** (least-priv — only the puller's SA gets `secretAccessor`):
   ```
   echo -n "<azure-ad-client-secret>" | gcloud secrets create AZURE_AD_CLIENT_SECRET \
     --data-file=- --project=oet-telemetry
   ```
3. **Set the non-secret config** as function env (`.env` for the `oet` codebase or `firebase functions:config`):
   `OET_AZURE_TENANT`, `OET_AZURE_CLIENT_ID`, `OET_MSSTORE_PRODUCT_ID` (e.g. `9ND80M1TT3JH`).
4. `firebase deploy --only functions:oet` redeploys both functions. The puller pulls **yesterday's**
   acquisitions daily and streams GA4-shaped rows into `oet.oet_events` (aggregate-correct; demographics
   never mapped). Verify in BigQuery + the function logs (`component: oet-msstore-puller`).

## Per-install keys (GL3 / C9) — per-`client_id` HMAC secrets
By default the endpoint verifies every request against the single shared `OET_HMAC_SECRET`. GL3 adds
**per-install keying**, OFF by default, flipped on with one env var:
```
OET_PER_INSTALL_KEYS=1
```
When on, each request's key is resolved **per `client_id`** from Secret Manager (`oet-client-<client_id>`,
in-process TTL cache ~5 min); unknown/unprovisioned/revoked ids **fail closed** (401). The shared
`OET_HMAC_SECRET` is then unused for `ingest` (mixed mode is not wired — pick one model).

**Provision one install** (Owner/DEVOPS — `client_id` must match `^[A-Za-z0-9_-]{1,64}$`):
```
openssl rand -base64 48 | tr -d '\n' | gcloud secrets create "oet-client-<client_id>" \
  --data-file=- --replication-policy=automatic --project=oet-telemetry
# hand <client_id> + the secret to that install over a trusted channel (your client agents integrate).
```
**Rotate**: `gcloud secrets versions add oet-client-<client_id> --data-file=-` — the resolver reads
`versions/latest`, so new requests pick it up within the cache TTL.
**Revoke**: `gcloud secrets delete oet-client-<client_id>` (or disable latest) — stops verifying within
one cache TTL.

**Least-priv IAM** — grant the runtime SA `secretAccessor` ONLY on the per-install secrets:
```
gcloud secrets add-iam-policy-binding "oet-client-<client_id>" \
  --member="serviceAccount:<runtime-sa>@oet-telemetry.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor" --project=oet-telemetry
```

> **KS-OUTAGE (done):** the reader distinguishes NOT_FOUND (→ 401 bad-key, negative-cached) from a
> transient Secret-Manager fault (→ retryable 503, NOT cached), so a blip can't lock out a legit install.

## `POST /provision` — automated first-run key minting (RP1–RP6)
For a *mass/shipped* untrusted client, the manual `gcloud` provisioning above doesn't scale — the client
must obtain its per-install key on first run. The `provision` function does this. It is **OFF by default
and `invoker: private`** — it is NOT publicly exposed until the SEC follow-up gate (RP1–RP6) clears.

```
OET_PROVISION_ENABLED=1     # enable the endpoint (controlled installs only until the SEC gate clears)
```
Flow: `POST /provision` with a Firebase **App Check** token header → size-cap → attestation (App Check,
**replay-consumed** so one token mints once) → per-IP + global **mint ceiling** (shared store, fail-closed)
→ **atomic** `createSecret oet-client-<random>` + first version → `201 {client_id, key}` **once**. Unknown
attestation → 401; ceiling hit → 429; Secret-Manager blip → 503 (retryable). The key is never logged.

**Least-priv IAM (RP5)** — the provisioner needs **create** rights, a SEPARATE, broader grant than the
ingest reader's `secretAccessor`. Scope it to the `oet-client-*` namespace (do NOT grant project-wide):
```
# the provision function's runtime SA → secretmanager.admin, scoped by a naming-convention IAM condition:
gcloud projects add-iam-policy-binding oet-telemetry \
  --member="serviceAccount:<provision-sa>@oet-telemetry.iam.gserviceaccount.com" \
  --role="roles/secretmanager.admin" \
  --condition='expression=resource.name.startsWith("projects/oet-telemetry/secrets/oet-client-"),title=oet-client-only'
```
Also enable **App Check token replay protection** (the `consume:true` path):
`gcloud services enable firebaseappcheck.googleapis.com`.

**Rotation / revoke (RP6)** — same as GL3: rotate = `gcloud secrets versions add oet-client-<id>`; revoke =
`gcloud secrets delete oet-client-<id>`. One-mint-per-attested-token is enforced by App Check consume; a
true per-device cap and a self-serve rotation endpoint are follow-ups.

> **⛔ Binding before a public `/provision`:** the real wiring above must clear SEC's **RP1–RP6 follow-up
> gate**. RP1 (CSPRNG), RP2 (atomic create), RP3 (App Check + consume-replay), RP4 (shared-store ceiling)
> are in code; RP5 (HTTPS+least-priv IAM) and the App Check replay API are the deploy steps here; RP6
> (per-device cap + rotation flow) is partially deferred. Keep `invoker: private` until SEC signs off.
