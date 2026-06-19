/**
 * Provisioning adapters — the real, injectable deps for `handleProvision` that need crypto/HTTP but NO
 * GCP SDK (RP1 generators + the HTTP wrapper). The Secret-Manager `KeyProvisioner`, the Firestore mint
 * gate, and the App Check verifier live in the deploy wrapper (`functions/`).
 */
import { randomBytes } from "node:crypto";
import {
  handleProvision,
  MAX_PROVISION_BODY_BYTES,
  type ProvisionDeps,
} from "./provision.js";
import type { PowSolution } from "./provision-pow.js";
import { CLIENT_ID_KEY_PATTERN } from "./ingest-adapter.js";
import type { RawHttpRequest, HttpResult } from "./ingest-adapter.js";

/**
 * RP1 — CSPRNG generators. `generateClientId` = 128 bits → base64url (22 url-safe chars, always matches
 * `CLIENT_ID_KEY_PATTERN`). `generateKey` = 256 bits → base64. Both from `crypto.randomBytes` (CSPRNG),
 * never `Math.random`. The key is returned to the caller ONCE and is never logged.
 */
export function createCryptoProvisionGen(): Pick<ProvisionDeps, "generateClientId" | "generateKey"> {
  return {
    generateClientId: () => randomBytes(16).toString("base64url"), // 22 chars of [A-Za-z0-9_-]
    generateKey: () => randomBytes(32).toString("base64"), // 256-bit shared secret
  };
}

/** Sanity self-check used by tests: the generated id must satisfy the ingest charset (defense-in-depth). */
export const PROVISION_CLIENT_ID_PATTERN = CLIENT_ID_KEY_PATTERN;

export interface ProvisionAdapterDeps extends ProvisionDeps {
  /** Header carrying the attestation (App Check) token (default `x-firebase-appcheck`). */
  attestationHeader?: string;
  /** Header carrying the Steam ownership/session token (default `x-oet-entitlement`). */
  entitlementHeader?: string;
}

function jsonResult(status: number, body: unknown, extra: Record<string, string> = {}): HttpResult {
  return { status, headers: { "content-type": "application/json", ...extra }, body: JSON.stringify(body) };
}

/** Parse a `{challenge, sig, nonce}` PoW solution from the JSON body; undefined if absent/malformed. */
function parsePow(rawBody: string): PowSolution | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null) return undefined;
  const { challenge, sig, nonce } = parsed as Record<string, unknown>;
  if (typeof challenge !== "string" || typeof sig !== "string" || typeof nonce !== "string") return undefined;
  return { challenge, sig, nonce };
}

/**
 * Build the `POST /provision` HTTP handler over the pure core. Caps the body at the transport (before the
 * core re-checks it), lifts the attestation token out of its header, maps the core response to HTTP with
 * **opaque bodies** and a `Retry-After` on the retryable 429/503. A 201 returns the minted credentials
 * once. Any unexpected throw becomes an opaque 500 (never leak which step/secret failed).
 */
export function createProvisionHttpHandler(deps: ProvisionAdapterDeps) {
  const header = deps.attestationHeader ?? "x-firebase-appcheck";
  const entHeader = deps.entitlementHeader ?? "x-oet-entitlement";
  return async (httpReq: RawHttpRequest): Promise<HttpResult> => {
    if (Buffer.byteLength(httpReq.rawBody, "utf8") > MAX_PROVISION_BODY_BYTES) {
      return jsonResult(413, { error: "payload_too_large" });
    }
    const token = httpReq.headers[header];
    const entitlementToken = httpReq.headers[entHeader];
    // A4 / PW — lift a solved challenge {challenge, sig, nonce} out of the JSON body (PoW mode). A
    // malformed body just means "no pow"; handleProvision rejects (proof_required) when PoW is configured.
    const pow = parsePow(httpReq.rawBody);
    let res;
    try {
      res = await handleProvision(
        {
          rawBody: httpReq.rawBody,
          ...(httpReq.ip !== undefined ? { ip: httpReq.ip } : {}),
          ...(token !== undefined ? { attestationToken: token } : {}),
          ...(entitlementToken !== undefined ? { entitlementToken } : {}),
          ...(pow !== undefined ? { pow } : {}),
        },
        deps,
      );
    } catch {
      return jsonResult(500, { error: "internal" });
    }
    const extra =
      res.status === 429 ? { "retry-after": "3600" } // a mint-ceiling resets on the window (1 h)
      : res.status === 503 ? { "retry-after": "5" }
      : {};
    return jsonResult(res.status, res.body, extra);
  };
}
