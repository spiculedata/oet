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
import {
  createIngestHttpHandler,
  makeHmacVerifier,
  createInMemoryRateLimiter,
  createInMemoryReplayCache,
  createCoarseGeo,
  makeBqInsert,
  DEFAULT_ALLOWLIST,
} from "oet";

const OET_HMAC_SECRET = defineSecret("OET_HMAC_SECRET");
const DATASET = process.env.OET_DATASET ?? "oet";
const TABLE = process.env.OET_TABLE ?? "oet_events";

const bq = new BigQuery();
const now = (): number => Date.now();

// Limiter + replay nonce cache. These in-memory impls are correct ONLY on a single instance — with
// >1 instance the limit is enforced ~N× too weakly and a nonce on one instance is invisible to the
// others (D-STORE). We therefore pin maxInstances=1 below for the locked-down phase. Before opening to
// public (`allUsers`) traffic, swap these for the SHARED-store impls — createSharedRateLimiter /
// createSharedReplayCache from the `oet` package over a Firestore-backed SharedStore — which lifts the
// single-instance cap. (Shared-store wiring needs firebase-admin Firestore → applied at the real deploy.)
const rateLimiter = createInMemoryRateLimiter({ now });
const replayCache = createInMemoryReplayCache(now);

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
    rateLimiter,
    replayCache,
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
    invoker: "private", // locked down — see file header
    maxInstances: 1, // D-STORE: in-memory limiter/nonce are single-instance-correct only. Raise once
    // the shared-store impls (createSharedRateLimiter/createSharedReplayCache) are wired (before public traffic).
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
