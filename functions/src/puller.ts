/**
 * MS Store Analytics acquisitions puller — scheduled Cloud Function (GL1).
 *
 * `onSchedule` provisions Cloud Scheduler → Pub/Sub under the hood. Each daily run gets an Azure AD
 * client-credentials token (client secret from Secret Manager, least-priv), fetches the acquisitions
 * report via the live source, normalizes it through `runAcquisitionPull`, and streams GA4 rows to the
 * same `oet.oet_events` table (with the per-row `insertId` dedup).
 *
 * A REAL run needs Owner inputs (env/secret): the Azure AD tenant + client id, the Store `productId`
 * (e.g. `9ND80M1TT3JH`), and the `AZURE_AD_CLIENT_SECRET` secret. Until those exist it deploys but
 * no-ops on missing config — no real call happens without the Owner's setup.
 */
import { onSchedule } from "firebase-functions/v2/scheduler";
import { defineSecret } from "firebase-functions/params";
import { BigQuery } from "@google-cloud/bigquery";
import {
  createAzureAdTokenIssuer,
  createMsStoreAcquisitionSource,
  runAcquisitionPull,
  makeBqInsert,
  type FetchJson,
} from "oet";

const AZURE_AD_CLIENT_SECRET = defineSecret("AZURE_AD_CLIENT_SECRET");
const TENANT = process.env.OET_AZURE_TENANT ?? "";
const CLIENT_ID = process.env.OET_AZURE_CLIENT_ID ?? "";
const PRODUCT_ID = process.env.OET_MSSTORE_PRODUCT_ID ?? "";
const DATASET = process.env.OET_DATASET ?? "oet";
const TABLE = process.env.OET_TABLE ?? "oet_events";

const bq = new BigQuery();

/** Real `fetch` → the injected `FetchJson` shape (Node 20+ has global fetch). */
const fetchJson: FetchJson = async (url, init) => {
  const r = await fetch(url, init);
  return { status: r.status, json: () => r.json() };
};

const log = (msg: string): void => console.log(JSON.stringify({ component: "oet-msstore-puller", msg }));

export const msstoreAcquisitionsPull = onSchedule(
  {
    schedule: "every day 03:00",
    timeZone: "Etc/UTC",
    region: process.env.OET_REGION ?? "us-central1",
    secrets: [AZURE_AD_CLIENT_SECRET],
    retryCount: 3,
  },
  async () => {
    if (!TENANT || !CLIENT_ID || !PRODUCT_ID) {
      log("skipped: Azure AD tenant / client id / productId not configured (Owner setup pending)");
      return;
    }
    const getToken = createAzureAdTokenIssuer(
      {
        tokenEndpoint: `https://login.microsoftonline.com/${TENANT}/oauth2/token`,
        clientId: CLIENT_ID,
        getClientSecret: async () => AZURE_AD_CLIENT_SECRET.value(),
        resource: "https://manage.devcenter.microsoft.com",
      },
      fetchJson,
    );
    const source = createMsStoreAcquisitionSource({ productId: PRODUCT_ID, getToken }, fetchJson);
    const bqInsert = makeBqInsert({
      insertRows: async (rows, insertIds) => {
        await bq
          .dataset(DATASET)
          .table(TABLE)
          .insert(
            rows.map((json, i) => ({ insertId: insertIds?.[i], json })) as unknown as object[],
            { raw: true },
          );
      },
    });
    // The acquisitions report lags ~a day; pull yesterday (UTC).
    const day = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const res = await runAcquisitionPull(day, day, { source, bqInsert, log });
    console.log(JSON.stringify({ component: "oet-msstore-puller", day, ...res }));
  },
);
