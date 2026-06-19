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
import { onRequest } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import { BigQuery } from "@google-cloud/bigquery";
import { initializeApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import {
  createIngestHttpHandler,
  makeHmacVerifier,
  createSharedRateLimiter,
  createSharedReplayCache,
  createInMemoryIpRateGate,
  createCoarseGeo,
  makeBqInsert,
  DEFAULT_ALLOWLIST,
} from "oet";
import { createFirestoreSharedStore } from "./firestore-store.js";

const OET_HMAC_SECRET = defineSecret("OET_HMAC_SECRET");
const DATASET = process.env.OET_DATASET ?? "oet";
const TABLE = process.env.OET_TABLE ?? "oet_events";

const bq = new BigQuery();
const now = (): number => Date.now();

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
    verifyHmac: makeHmacVerifier(() => OET_HMAC_SECRET.value()),
    ipRateGate,
    rateLimiter,
    replayCache,
    // F5: PII-free structured security log (the event carries only outcome/status/coarse reason —
    // never client_id/user_id/IP/secret/body). Cloud Logging ingests the JSON for alerting.
    onSecurityEvent: (e) => console.warn(JSON.stringify({ severity: "WARNING", component: "oet-ingest", ...e })),
    // No IP→country provider wired yet → geo stays null (gaps stay gaps, DOMAIN LAW 6). Add a coarse
    // geo provider (country-only, EC1) before geo columns are populated.
    deriveGeo: createCoarseGeo({ lookupCountry: () => null }),
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
