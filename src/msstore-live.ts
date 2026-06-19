/**
 * Live Microsoft Store Analytics acquisition source (GL1).
 *
 * Implements `AcquisitionSource` over the real Store Analytics "acquisitions" report, authenticated by
 * an OAuth2 **client-credentials** token from **Azure AD**. So `runAcquisitionPull` drives it unchanged
 * (live source → normalize → write). Everything I/O is INJECTED — an HTTP `FetchJson` and a
 * `getClientSecret()` provider (real: Secret Manager, least-priv) — so there are NO real creds/SDK here
 * and it's fully testable with a mock token issuer + recorded fixtures.
 *
 * API shapes (documented Partner Center / Azure AD; we do not invent fields):
 *  - token: POST `<tenant>/oauth2/token` form `grant_type=client_credentials` → `{ access_token, expires_in }`
 *  - acquisitions: GET `.../v1.0/my/analytics/acquisitions?applicationId=&startDate=&endDate=` (Bearer),
 *    response `{ Value: [...], "@nextLink"? }`. Demographic fields (ageGroup/gender) are NOT mapped (PII).
 */
import type { AcquisitionSource, MsStoreAcquisitionRow } from "./msstore-puller.js";

/** Minimal JSON-over-HTTP shape we depend on (real: a `fetch` wrapper; tests: a fixture stub). */
export type FetchJson = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{ status: number; json: () => Promise<unknown> }>;

// ── I1 (audit #2): Azure config shape validation (defense-in-depth on the OAuth URL) ──────────────────
// The tenant is interpolated into `https://login.microsoftonline.com/<tenant>/oauth2/token`. A malformed
// tenant could distort that URL (extra path segments / scheme), so we shape-check it (and the client id)
// before any token call. A valid tenant is a GUID or an Entra domain (e.g. `contoso.onmicrosoft.com`);
// a client id is a GUID-like token. Neither may contain `/`, `:`, whitespace, or other URL metacharacters.
/** True if `s` is a safe Azure AD **tenant** id (GUID or domain) — no URL-structural characters. */
export function isValidAzureTenant(s: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9.-]{0,126}$/.test(s);
}
/** True if `s` is a safe Azure AD **client** id (GUID-like) — no URL-structural characters. */
export function isValidAzureClientId(s: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9-]{0,127}$/.test(s);
}

export interface AzureAdConfig {
  /** Azure AD v1 token endpoint, e.g. `https://login.microsoftonline.com/<tenant>/oauth2/token`. */
  tokenEndpoint: string;
  clientId: string;
  /** Resolves the client secret out-of-band (real: Secret Manager). Never stored/logged here. */
  getClientSecret: () => Promise<string>;
  /** The resource the token is for — Store Analytics: `https://manage.devcenter.microsoft.com`. */
  resource: string;
}

/**
 * Azure AD client-credentials token issuer, caching the token in-memory until ~1 min before expiry so a
 * warm scheduler instance doesn't re-auth every run.
 */
export function createAzureAdTokenIssuer(
  cfg: AzureAdConfig,
  fetchJson: FetchJson,
  now: () => number = Date.now,
): () => Promise<string> {
  let cached: { token: string; expiresAtMs: number } | null = null;
  return async () => {
    const t = now();
    if (cached && cached.expiresAtMs - 60_000 > t) return cached.token;
    const secret = await cfg.getClientSecret();
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: cfg.clientId,
      client_secret: secret,
      resource: cfg.resource,
    }).toString();
    const res = await fetchJson(cfg.tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    if (res.status !== 200) throw new Error(`azure_ad_token_failed:${res.status}`);
    const data = (await res.json()) as { access_token?: string; expires_in?: string | number };
    if (typeof data.access_token !== "string") throw new Error("azure_ad_token_missing");
    const expiresInSec = Number(data.expires_in ?? 3600);
    cached = { token: data.access_token, expiresAtMs: t + expiresInSec * 1000 };
    return cached.token;
  };
}

export interface MsStoreSourceConfig {
  /** Store product id (the API's `applicationId`), e.g. "9ND80M1TT3JH". */
  productId: string;
  /** API base; default `https://manage.devcenter.microsoft.com`. */
  baseUrl?: string;
  getToken: () => Promise<string>;
}

/** Map one raw API row to the normalizer's input — only the non-PII fields (ageGroup/gender dropped). */
function toRow(v: Record<string, unknown>): MsStoreAcquisitionRow | null {
  if (typeof v.date !== "string") return null;
  const row: MsStoreAcquisitionRow = { date: v.date };
  if (typeof v.acquisitionType === "string") row.acquisitionType = v.acquisitionType;
  if (typeof v.market === "string") row.market = v.market;
  if (typeof v.osVersion === "string") row.osVersion = v.osVersion;
  if (typeof v.deviceType === "string") row.deviceType = v.deviceType;
  if (typeof v.storeClient === "string") row.storeClient = v.storeClient;
  if (typeof v.acquisitionQuantity === "number") row.acquisitionQuantity = v.acquisitionQuantity;
  return row;
}

/** An `AcquisitionSource` over the live Store Analytics acquisitions report (Bearer auth, paginated). */
export function createMsStoreAcquisitionSource(
  cfg: MsStoreSourceConfig,
  fetchJson: FetchJson,
): AcquisitionSource {
  const base = cfg.baseUrl ?? "https://manage.devcenter.microsoft.com";
  return {
    async fetch(startDate, endDate) {
      const token = await cfg.getToken();
      const headers = { authorization: `Bearer ${token}`, accept: "application/json" };
      let url: string | undefined =
        `${base}/v1.0/my/analytics/acquisitions?applicationId=${encodeURIComponent(cfg.productId)}` +
        `&startDate=${encodeURIComponent(startDate)}&endDate=${encodeURIComponent(endDate)}&top=1000`;
      const out: MsStoreAcquisitionRow[] = [];
      let guard = 0;
      while (url !== undefined && guard++ < 10_000) {
        const res = await fetchJson(url, { method: "GET", headers });
        if (res.status !== 200) throw new Error(`msstore_acquisitions_failed:${res.status}`);
        const data = (await res.json()) as { Value?: unknown[]; "@nextLink"?: string };
        for (const v of data.Value ?? []) {
          if (v !== null && typeof v === "object") {
            const row = toRow(v as Record<string, unknown>);
            if (row !== null) out.push(row);
          }
        }
        const next = data["@nextLink"];
        if (typeof next === "string" && next.length > 0) {
          const resolved = next.startsWith("http") ? next : `${base}${next}`;
          // GL-SSRF: only follow a `@nextLink` whose **origin** (scheme + host + port) matches the
          // configured base. A tampered/poisoned link elsewhere is a server-side request forgery — and
          // comparing the *origin* (not just `.host`) also refuses a same-host **https→http downgrade**,
          // which would otherwise send the OAuth Bearer token over cleartext (QA residual on the host-only
          // check). We additionally require https outright, so the token never leaves over plaintext.
          const target = new URL(resolved);
          if (target.protocol !== "https:" || target.origin !== new URL(base).origin) {
            throw new Error(`msstore_nextlink_host_mismatch:${target.origin}`);
          }
          url = resolved;
        } else {
          url = undefined;
        }
      }
      return out;
    },
  };
}
