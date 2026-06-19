/**
 * OET ingestion endpoint — Firebase Cloud Function (gen 2) entry point. This is the THIN deploy
 * wrapper: it wires the OET core's pure `createIngestHttpHandler` to real runtime deps and exposes
 * it as an HTTPS function. The security logic lives in the `oet` package (already SEC/QA-gated).
 *
 * LOCKED DOWN by design (`invoker: "private"`) — only IAM-authenticated callers, NOT the public
 * internet. It is opened to unauthenticated public traffic only AFTER the C8/SP1 signed-`sent_at`
 * replay-freshness defense lands (SEC's binding pre-traffic condition). See deploy/RUNBOOK.md.
 *
 * Deploys to the `oet-telemetry` project as the isolated `oet` functions codebase; writes to the
 * dedicated `oet.oet_events` BigQuery dataset (created by deploy/bq-setup.sh).
 */
// GL1: the daily MS Store acquisitions puller (scheduled function) is its own module; re-export so
// Firebase discovers it alongside `ingest`.
export { msstoreAcquisitionsPull } from "./puller.js";
import { onRequest } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import { BigQuery } from "@google-cloud/bigquery";
import { initializeApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import { getAppCheck } from "firebase-admin/app-check";
import {
  createIngestHttpHandler,
  makeHmacVerifier,
  createPerInstallKeyResolver,
  createSharedRateLimiter,
  createSharedReplayCache,
  createSharedProvisionGate,
  createInMemoryIpRateGate,
  createCoarseGeo,
  createAppCheckVerifier,
  createCryptoProvisionGen,
  createProvisionHttpHandler,
  makeBqInsert,
  DEFAULT_ALLOWLIST,
  type SecretLookup,
} from "oet";
import { createFirestoreSharedStore } from "./firestore-store.js";
import { createSecretManagerKeyStore } from "./secret-keystore.js";
import { createSecretManagerKeyProvisioner } from "./provision-keystore.js";

const OET_HMAC_SECRET = defineSecret("OET_HMAC_SECRET");
const DATASET = process.env.OET_DATASET ?? "oet";
const TABLE = process.env.OET_TABLE ?? "oet_events";

const bq = new BigQuery();
const now = (): number => Date.now();

// GL3 / C9 — per-install keys. OFF by default → the single shared `OET_HMAC_SECRET` path (unchanged).
// When `OET_PER_INSTALL_KEYS=1`, each request's key is resolved per `client_id` from Secret Manager
// (`oet-client-<client_id>`, cached in-process); unknown/unprovisioned ids fail closed. Provisioning +
// least-priv IAM are Owner/DEVOPS steps — see deploy/RUNBOOK.md "Per-install keys (GL3 / C9)".
const PER_INSTALL_KEYS = process.env.OET_PER_INSTALL_KEYS === "1";
function buildSecretLookup(): SecretLookup {
  if (!PER_INSTALL_KEYS) return () => OET_HMAC_SECRET.value();
  const projectId = process.env.GCLOUD_PROJECT ?? process.env.GOOGLE_CLOUD_PROJECT ?? "oet-telemetry";
  return createPerInstallKeyResolver(createSecretManagerKeyStore(projectId), { now });
}

// Limiter + replay nonce cache over a SHARED Firestore store, so they're correct across >1 instance
// (D-STORE) AND race-free (atomic claim/transaction; D-STORE-CAS). This is what makes raising
// maxInstances > 1 safe — see below. The Firestore TTL policy on `expiresAt` (deploy/RUNBOOK.md) reaps
// expired nonce/counter docs; correctness comes from the in-transaction expiry check, not the reaper.
initializeApp();
const sharedStore = createFirestoreSharedStore(getFirestore());
const rateLimiter = createSharedRateLimiter(sharedStore, { now });
const replayCache = createSharedReplayCache(sharedStore);
// F2: cheap per-instance, no-I/O pre-auth flood gate in front of all the above.
const ipRateGate = createInMemoryIpRateGate({ now });

const bqInsert = makeBqInsert({
  insertRows: async (rows, insertIds) => {
    // raw insert with a per-row insertId → BigQuery best-effort dedup on retry (F-WRITE-DEDUP).
    await bq
      .dataset(DATASET)
      .table(TABLE)
      .insert(
        rows.map((json, i) => ({ insertId: insertIds?.[i], json })) as unknown as object[],
        { raw: true },
      );
  },
});

let handler: ReturnType<typeof createIngestHttpHandler> | undefined;
function getHandler(): ReturnType<typeof createIngestHttpHandler> {
  handler ??= createIngestHttpHandler({
    now,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: makeHmacVerifier(buildSecretLookup()),
    ipRateGate,
    rateLimiter,
    replayCache,
    // F5: PII-free structured security log (the event carries only outcome/status/coarse reason —
    // never client_id/user_id/IP/secret/body). Cloud Logging ingests the JSON for alerting.
    onSecurityEvent: (e) => console.warn(JSON.stringify({ severity: "WARNING", component: "oet-ingest", ...e })),
    // GL2 geo: country-only from a TRUSTED edge header (raw IP never used). Falls back to the null
    // provider when no header is configured (gaps stay gaps). Set OET_COUNTRY_HEADER to enable.
    deriveGeo: createCoarseGeo({ lookupCountry: () => null }),
    ...(process.env.OET_COUNTRY_HEADER ? { trustedCountryHeader: process.env.OET_COUNTRY_HEADER } : {}),
    // GL2 App Check: real firebase-admin verification, OFF by default (Owner sets OET_APP_CHECK_ENABLED=true
    // once App Check is configured). While off, the F10 guard ignores a stray header and HMAC runs.
    ...(process.env.OET_APP_CHECK_ENABLED === "true"
      ? { verifyAppCheckToken: createAppCheckVerifier((t) => getAppCheck().verifyToken(t)) }
      : {}),
    bqInsert,
  });
  return handler;
}

export const ingest = onRequest(
  {
    region: process.env.OET_REGION ?? "us-central1",
    secrets: [OET_HMAC_SECRET],
    invoker: "private", // locked down — open to `allUsers` only when the Owner is ready for public traffic
    maxInstances: 10, // safe now: limiter + replay nonce are on the SHARED Firestore store (D-STORE/-CAS)
    memory: "256MiB",
  },
  async (req, res) => {
    const raw = (req.rawBody ?? Buffer.from(JSON.stringify(req.body ?? {}), "utf8")).toString("utf8");
    const result = await getHandler()({
      headers: req.headers as Record<string, string | undefined>,
      rawBody: raw,
      ip: req.ip,
    });
    res.status(result.status).set(result.headers).send(result.body);
  },
);

// ── RP1–RP6: per-install key PROVISIONING endpoint (`POST /provision`) ────────────────────────────────
// Mints {client_id, key} for a first-run untrusted client. OFF by default and `invoker: "private"` —
// it is NOT publicly exposed until the real wiring clears SEC's follow-up gate (RP1–RP6). Enable with
// `OET_PROVISION_ENABLED=1` (controlled installs only until that gate). Wiring:
//   RP1 CSPRNG id/key (createCryptoProvisionGen)
//   RP2 atomic Secret-Manager createSecret (createSecretManagerKeyProvisioner)
//   RP3 real App Check + CONSUME-token replay — verifyToken(..,{consume:true}); a re-used token
//       (alreadyConsumed) returns false → one token can't farm many mints
//   RP4 shared-store (cross-instance) per-IP + global mint ceiling (createSharedProvisionGate), fail-closed
//   RP5 HTTPS-only (onRequest) + private invoker; least-priv `secretCreator` on `oet-client-*` = deploy/IAM
const PROVISION_ENABLED = process.env.OET_PROVISION_ENABLED === "1";
let provisionHandler: ReturnType<typeof createProvisionHttpHandler> | undefined;
function getProvisionHandler(): ReturnType<typeof createProvisionHttpHandler> {
  const projectId = process.env.GCLOUD_PROJECT ?? process.env.GOOGLE_CLOUD_PROJECT ?? "oet-telemetry";
  provisionHandler ??= createProvisionHttpHandler({
    now,
    // RP3: App Check verify WITH replay consumption — first use verifies, a replayed token is rejected.
    verifyAttestation: async (token) => {
      const r = await getAppCheck().verifyToken(token, { consume: true });
      return r.alreadyConsumed !== true; // genuine AND not already spent
    },
    // RP4: cross-instance per-IP + global mint ceiling, fail-closed on store outage.
    gate: createSharedProvisionGate(sharedStore, { now }),
    ...createCryptoProvisionGen(), // RP1
    keyProvisioner: createSecretManagerKeyProvisioner(projectId), // RP2
    onSecurityEvent: (e) => console.warn(JSON.stringify({ severity: "WARNING", component: "oet-provision", ...e })),
  });
  return provisionHandler;
}

export const provision = onRequest(
  {
    region: process.env.OET_REGION ?? "us-central1",
    invoker: "private", // NOT public until RP1–RP6 clear SEC's follow-up gate
    maxInstances: 3, // minting is rare + paid; keep it tight
    memory: "256MiB",
  },
  async (req, res) => {
    if (!PROVISION_ENABLED) {
      res.status(404).set({ "content-type": "application/json" }).send(JSON.stringify({ error: "not_found" }));
      return;
    }
    const raw = (req.rawBody ?? Buffer.from(JSON.stringify(req.body ?? {}), "utf8")).toString("utf8");
    const result = await getProvisionHandler()({
      headers: req.headers as Record<string, string | undefined>,
      rawBody: raw,
      ip: req.ip,
    });
    res.status(result.status).set(result.headers).send(result.body);
  },
);
