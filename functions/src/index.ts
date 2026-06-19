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
  createDerivedKeyStore,
  createSharedRateLimiter,
  createSharedReplayCache,
  createSharedProvisionGate,
  createInMemoryIpRateGate,
  createCoarseGeo,
  createCryptoProvisionGen,
  createProvisionHttpHandler,
  issueChallenge,
  verifyPowChallenge,
  createSteamEntitlementVerifier,
  deriveClientKey,
  makeBqInsert,
  DEFAULT_ALLOWLIST,
  type SecretLookup,
  type FetchJson,
} from "oet";
import { randomBytes } from "node:crypto";
import { createFirestoreSharedStore } from "./firestore-store.js";
import { createSecretManagerKeyStore } from "./secret-keystore.js";
import { createSecretManagerKeyProvisioner } from "./provision-keystore.js";
import { createFirestoreRevocationList } from "./derived-keystore.js";

const OET_HMAC_SECRET = defineSecret("OET_HMAC_SECRET");
const OET_DERIVED_ROOT_KEY = defineSecret("OET_DERIVED_ROOT_KEY"); // DK1 — only required in derived mode
const OET_PROVISION_POW_KEY = defineSecret("OET_PROVISION_POW_KEY"); // A4/PW — only required when PoW is on
const STEAM_WEB_API_KEY = defineSecret("STEAM_WEB_API_KEY"); // A4/Steam — only required when entitlement is on
const DATASET = process.env.OET_DATASET ?? "oet";
const TABLE = process.env.OET_TABLE ?? "oet_events";

const bq = new BigQuery();
const now = (): number => Date.now();

// GL3 / C9 — per-install keys. OFF by default → the single shared `OET_HMAC_SECRET` path (unchanged).
// When `OET_PER_INSTALL_KEYS=1`, each request's key is resolved per `client_id` from Secret Manager
// (`oet-client-<client_id>`, cached in-process); unknown/unprovisioned ids fail closed. Provisioning +
// least-priv IAM are Owner/DEVOPS steps — see deploy/RUNBOOK.md "Per-install keys (GL3 / C9)".
const PER_INSTALL_KEYS = process.env.OET_PER_INSTALL_KEYS === "1";
// DK4 — pick ONE per-install key model per deploy: "secret" (GL3, one Secret-Manager secret per install)
// or "derived" (A3/DK, HKDF from one root key). Default "secret" → unchanged behavior.
const KEY_MODEL = process.env.OET_KEY_MODEL === "derived" ? "derived" : "secret";
const DERIVED_KEY_VERSION = process.env.OET_DERIVED_KEY_VERSION ?? "v1"; // DK3 rotation lever
function buildSecretLookup(): SecretLookup {
  if (!PER_INSTALL_KEYS) return () => OET_HMAC_SECRET.value();
  if (KEY_MODEL === "derived") {
    // A3/DK: derive each install's key from ONE root key (DK1, Secret Manager) + a Firestore revocation
    // deny-list (DK2, fail-closed → 503 on outage); rotate via OET_DERIVED_KEY_VERSION + a new root (DK3).
    return createPerInstallKeyResolver(
      createDerivedKeyStore({
        getRootKey: () => OET_DERIVED_ROOT_KEY.value(),
        keyVersion: DERIVED_KEY_VERSION,
        revocationList: createFirestoreRevocationList(getFirestore(), { now }),
      }),
      { now },
    );
  }
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
    // App Check (GL2 + A1/F4): real firebase-admin verification, OFF by default (Owner sets
    // OET_APP_CHECK_ENABLED=true once App Check is configured). While off, the F10 guard ignores a stray
    // header and HMAC runs. A1/F4: verify with `consume:true` so a token is single-use at the VERIFIER
    // layer too (alreadyConsumed → reject), complementing the core's token-keyed replay nonce. This
    // requires clients to send a FRESH **limited-use** App Check token per request (getLimitedUseToken).
    ...(process.env.OET_APP_CHECK_ENABLED === "true"
      ? {
          verifyAppCheckToken: async (t: string): Promise<boolean> => {
            try {
              const r = await getAppCheck().verifyToken(t, { consume: true });
              return r.alreadyConsumed !== true; // genuine AND not already spent (fail closed otherwise)
            } catch {
              return false;
            }
          },
        }
      : {}),
    bqInsert,
  });
  return handler;
}

export const ingest = onRequest(
  {
    region: process.env.OET_REGION ?? "us-central1",
    // DK1: the derived-model root key is only bound (and thus required to exist) when KEY_MODEL=derived.
    secrets: [OET_HMAC_SECRET, ...(KEY_MODEL === "derived" ? [OET_DERIVED_ROOT_KEY] : [])],
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
// A4 / PW — desktop proof-of-work. When OET_POW_ENABLED=1, minting requires a solved challenge (PW4) and
// `GET /provision` issues one (PW1). Difficulty (PW3) is tunable; the RP4 ceiling is still the hard cap.
const POW_ENABLED = process.env.OET_POW_ENABLED === "1";
const POW_DIFFICULTY = Number(process.env.OET_POW_DIFFICULTY ?? "20");
// PW-GET-FLOOD: a SEPARATE, more generous per-IP gate in front of `GET /provision` so unauthenticated
// challenge requests can't be used to flood App-Check verifies / Firestore. Distinct `keyPrefix` so it
// neither consumes nor is consumed by the mint ceiling. Fail-closed on a store outage.
const challengeGate = createSharedProvisionGate(sharedStore, { now, keyPrefix: "pvc", perIp: 30, globalCeiling: 5000 });
// A4 / Steam entitlement — required on the Steam channel. When OET_STEAM_ENTITLEMENT_REQUIRED=1, minting
// requires a server-verified Steam ownership ticket (header `x-oet-entitlement`). Fail-closed.
const STEAM_ENTITLEMENT_REQUIRED = process.env.OET_STEAM_ENTITLEMENT_REQUIRED === "1";
const STEAM_APP_ID = process.env.OET_STEAM_APP_ID ?? "";
/** Real `fetch` → the injected `FetchJson` shape (Node 20+ has global fetch). */
const steamFetchJson: FetchJson = async (url, init) => {
  const r = await fetch(url, init);
  return { status: r.status, json: () => r.json() };
};
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
    // DK4 — pick the SAME model the verifier uses: derived (issue id, return derived key, no createSecret)
    // or stored (RP2, Secret-Manager per install). Must match `OET_KEY_MODEL` so a minted key verifies.
    ...(KEY_MODEL === "derived"
      ? { deriveKey: (clientId: string) => deriveClientKey(clientId, OET_DERIVED_ROOT_KEY.value(), DERIVED_KEY_VERSION) }
      : { keyProvisioner: createSecretManagerKeyProvisioner(projectId) }),
    // A4 / PW4 + PW2: require a valid solved challenge, consumed single-use via the shared store.
    ...(POW_ENABLED
      ? {
          verifyProofOfWork: (sol) => verifyPowChallenge(sol, { now, hmacKey: OET_PROVISION_POW_KEY.value() }),
          consumeChallenge: (id) => sharedStore.claim(`powc:${id}`, now() + 5 * 60 * 1000),
        }
      : {}),
    // A4 / Steam: server-side ownership check (publisher Web API key from Secret Manager; never logged).
    ...(STEAM_ENTITLEMENT_REQUIRED
      ? {
          verifyEntitlement: createSteamEntitlementVerifier(
            { getWebApiKey: () => STEAM_WEB_API_KEY.value(), appId: STEAM_APP_ID },
            steamFetchJson,
          ),
        }
      : {}),
    onSecurityEvent: (e) => console.warn(JSON.stringify({ severity: "WARNING", component: "oet-provision", ...e })),
  });
  return provisionHandler;
}

/** PW1 — issue a fresh stateless signed challenge (requires a valid App Check token; no consume here). */
async function handleChallengeRequest(token: string | undefined, ip: string | undefined): Promise<{ status: number; body: string }> {
  // PW-GET-FLOOD: rate-limit BEFORE the App-Check verify so a flood can't drive verify/Firestore cost.
  if (!(await challengeGate.allow(ip))) {
    return { status: 429, body: JSON.stringify({ error: "rate_limited" }) };
  }
  let attested = false;
  if (token !== undefined) {
    try {
      await getAppCheck().verifyToken(token); // verify only — the mint POST consumes the (limited-use) token
      attested = true;
    } catch {
      attested = false;
    }
  }
  if (!attested) return { status: 401, body: JSON.stringify({ error: "unauthorized" }) };
  const c = issueChallenge({
    now,
    hmacKey: OET_PROVISION_POW_KEY.value(),
    difficulty: POW_DIFFICULTY,
    randomId: () => randomBytes(16).toString("base64url"),
  });
  return { status: 200, body: JSON.stringify({ challenge: c.challenge, sig: c.sig, difficulty: c.difficulty, exp: c.exp }) };
}

export const provision = onRequest(
  {
    region: process.env.OET_REGION ?? "us-central1",
    // Bind a secret only when its feature is on: the PoW signing key (PoW), the Steam Web API key
    // (entitlement), and the derived root key (derived model — provision derives the key the verifier does).
    secrets: [
      ...(POW_ENABLED ? [OET_PROVISION_POW_KEY] : []),
      ...(STEAM_ENTITLEMENT_REQUIRED ? [STEAM_WEB_API_KEY] : []),
      ...(KEY_MODEL === "derived" ? [OET_DERIVED_ROOT_KEY] : []),
    ],
    invoker: "private", // NOT public until RP1–RP6 clear SEC's follow-up gate
    maxInstances: 3, // minting is rare + paid; keep it tight
    memory: "256MiB",
  },
  async (req, res) => {
    if (!PROVISION_ENABLED) {
      res.status(404).set({ "content-type": "application/json" }).send(JSON.stringify({ error: "not_found" }));
      return;
    }
    // A4 / PW1 — GET issues a challenge (when PoW is on); POST mints.
    if (req.method === "GET") {
      if (!POW_ENABLED) {
        res.status(404).set({ "content-type": "application/json" }).send(JSON.stringify({ error: "not_found" }));
        return;
      }
      const c = await handleChallengeRequest(req.headers["x-firebase-appcheck"] as string | undefined, req.ip);
      res.status(c.status).set({ "content-type": "application/json" }).send(c.body);
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
