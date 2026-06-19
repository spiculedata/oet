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
- **Geo**: no IP→country provider wired yet → `geo` is null on every row. Add one (country-only,
  region behind a k-anon floor — EC1) before relying on geo.
- **App Check**: only HMAC is wired here. App Check (Firebase clients) is a follow-up using
  `firebase-admin` `appCheck().verifyToken` injected as `verifyAppCheckToken`.
- **Rate limiter / replay cache** are now backed by the **shared Firestore store** (`functions/src/firestore-store.ts`)
  — atomic `claim`/transaction, correct + race-free across instances (D-STORE / D-STORE-CAS), so the function
  runs at `maxInstances: 10`. Needs the Firestore database + TTL policies from step 3b.
- **Secret distribution**: `OET_HMAC_SECRET` is a single shared secret here. Per SEC ruling #1 / C9, a
  shipped untrusted client must NOT embed a global secret — use per-install provisioned keys or App Check
  before any real client ships with it.
