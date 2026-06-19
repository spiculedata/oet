# OET — GCP deploy runbook (Cloud Functions + BigQuery)

Target project: **`oet-telemetry`** — a **placeholder for a standalone OET GCP project** (OET is a
vendor-neutral protocol; it is NOT co-tenanted in any app's project). Replace it in `.firebaserc` with your
own OET project ID before deploying. Endpoint deploys as the isolated **`oet`** functions codebase; data
lands in the dedicated **`oet.oet_events`** BigQuery dataset.

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
2. **Confirm billing** is enabled on `oet-telemetry` (Cloud Functions gen2 + BigQuery are billed).
3. **Create the BigQuery dataset + table** (idempotent):
   ```
   bash deploy/bq-setup.sh oet-telemetry US
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
- **Rate limiter / replay cache** are in-memory (per warm instance). For multi-instance correctness at
  scale, back them with a shared store (Firestore/Redis) — fine for the locked-down validation phase.
- **Secret distribution**: `OET_HMAC_SECRET` is a single shared secret here. Per SEC ruling #1 / C9, a
  shipped untrusted client must NOT embed a global secret — use per-install provisioned keys or App Check
  before any real client ships with it.
