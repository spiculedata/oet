/**
 * OET local smoke proof — runs the REAL ingestion endpoint over real HTTP with a LOGGING BigQuery
 * writer (no real BigQuery, no GCP, no money). Drives it with the reference emitter (real HMAC sign)
 * and exercises the security behaviors. This is the same code path that deploys as the Cloud
 * Function — only `bqInsert` is swapped for a logger and the transport is local.
 *
 *   node deploy/smoke.mjs      (after `npm run build`)
 */
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import {
  createIngestHttpHandler,
  makeHmacVerifier,
  createInMemoryRateLimiter,
  createInMemoryReplayCache,
  createCoarseGeo,
  makeBqInsert,
  DEFAULT_ALLOWLIST,
  createEmitter,
  makeHmacSigner,
  canonicalEnvelope,
} from "../dist/index.js";

const SECRET = "smoke-secret";
const now = () => 1_700_000_000_000;
const written = [];

const handler = createIngestHttpHandler({
  now,
  allowlist: DEFAULT_ALLOWLIST,
  verifyHmac: makeHmacVerifier(() => SECRET),
  rateLimiter: createInMemoryRateLimiter({ now }),
  replayCache: createInMemoryReplayCache(now),
  deriveGeo: createCoarseGeo({ lookupCountry: () => "US" }),
  bqInsert: makeBqInsert({
    insertRows: async (rows, insertIds) => {
      written.push(...rows);
      console.log(`   [BQ MOCK] would insert ${rows.length} row(s) into oet.oet_events (insertIds: ${insertIds?.length ?? 0})`);
    },
  }),
});

const server = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", async () => {
    const r = await handler({ headers: {}, rawBody: body, ip: req.socket.remoteAddress ?? "127.0.0.1" });
    res.writeHead(r.status, r.headers);
    res.end(r.body);
  });
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/ingest`;
const post = async (bodyStr, headers = {}) => {
  const r = await fetch(url, { method: "POST", body: bodyStr, headers: { "content-type": "application/json", ...headers } });
  return { status: r.status, body: await r.text() };
};

console.log(`\nOET endpoint up at ${url}  —  LOGGING BigQuery mock, NO real GCP.\n`);
let pass = 0, fail = 0;
const check = (label, cond, detail = "") => { (cond ? (pass++, console.log(`✅ ${label} ${detail}`)) : (fail++, console.log(`❌ ${label} ${detail}`))); };

// 1) Happy path via the reference emitter (real client_id + HMAC sign + flush).
const emitter = createEmitter({
  endpoint: url,
  platform: "windows",
  appVersion: "2.2.0+27",
  consent: true,
  now,
  store: { load: () => null, save: () => {} },
  genId: () => "smoke-guid",
  sign: makeHmacSigner(SECRET),
  transport: { post: async (u, b, h) => ({ status: (await fetch(u, { method: "POST", body: b, headers: h })).status }) },
});
emitter.track("app_open", { source: "smoke" });
emitter.track("purchase", { amount: 4, total: 12.5 });
const flushed = await emitter.flush();
check("emitter flush → 202, both events written", flushed.ok && written.length === 2, `(client_id=${emitter.clientId}, sent=${flushed.sent})`);
check("server stamped GA4 event_timestamp (µs) + coarse geo", written[0]?.event_timestamp === now() * 1000 && written[0]?.geo?.country === "US");

// 2) Forged signature → 401, nothing written.
const before = written.length;
const SENT_AT = new Date(now()).toISOString(); // in-window vs the server clock (§5.4)
const forged = JSON.stringify({ client_id: "win-x", user_id: null, platform: "windows", app_version: "1", consent: true, sent_at: SENT_AT, events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }], sig: "hmac-sha256:WRONG" });
const r401 = await post(forged);
check("forged sig → 401, no write", r401.status === 401 && written.length === before);

// 3) Valid sig but consent:false → opaque 202, nothing written.
const noConsent = { client_id: "win-y", user_id: null, platform: "windows", app_version: "1", consent: false, sent_at: SENT_AT, events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }] };
noConsent.sig = "hmac-sha256:" + createHmac("sha256", SECRET).update(canonicalEnvelope(noConsent)).digest("base64");
const r202 = await post(JSON.stringify(noConsent));
check("consent:false → opaque 202, no write", r202.status === 202 && written.length === before);

// 4) Non-allowlisted event → opaque 202, dropped (no write).
const spam = { client_id: "win-z", user_id: null, platform: "windows", app_version: "1", consent: true, sent_at: SENT_AT, events: [{ name: "not_allowlisted", ts: "2026-06-18T00:00:00Z" }] };
spam.sig = "hmac-sha256:" + createHmac("sha256", SECRET).update(canonicalEnvelope(spam)).digest("base64");
const rSpam = await post(JSON.stringify(spam));
check("non-allowlisted event → 202, dropped", rSpam.status === 202 && written.length === before);

console.log(`\n${fail === 0 ? "✅ ALL PROVEN" : "❌ FAILURES"} — ${pass} passed, ${fail} failed. Rows the deploy would write to BigQuery: ${written.length}.\n`);
server.close();
process.exit(fail === 0 ? 0 : 1);
