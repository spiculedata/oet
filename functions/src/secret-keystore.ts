/**
 * GL3 / C9 — real per-install HMAC key store backed by **Secret Manager**.
 *
 * Each provisioned install has its own secret stored as `oet-client-<client_id>` (latest version).
 * The OET core's `createPerInstallKeyResolver` validates the `client_id` shape and caches results, so
 * this layer is intentionally thin: derive the resource name, fetch the latest version, return the
 * payload (or `undefined` if the secret/version doesn't exist → the resolver fails closed).
 *
 * Least-priv: the function's runtime service account is granted `secretAccessor` ONLY on the
 * `oet-client-*` secrets (see deploy/RUNBOOK.md), never project-wide. The secret value never leaves
 * this closure and is never logged (DOMAIN LAW 7).
 */
import { SecretManagerServiceClient } from "@google-cloud/secret-manager";
import { CLIENT_ID_KEY_PATTERN, KeyStoreUnavailableError, type PerInstallKeyStore } from "oet";

/** Prefix for per-install secret names. `oet-client-<client_id>` — client_id is shape-validated. */
const SECRET_NAME_PREFIX = "oet-client-";

/** gRPC status code for NOT_FOUND (a missing secret/version) — the unprovisioned/revoked case. */
const GRPC_NOT_FOUND = 5;

/**
 * Build a `PerInstallKeyStore` over Secret Manager for `projectId`. `getKey` returns the latest
 * secret-version payload for one install; resolves `undefined` when the secret is **NOT_FOUND**
 * (unprovisioned/revoked → fail closed); and **throws `KeyStoreUnavailableError`** on any other failure
 * (outage / perms blip / throttle / network) so the request gets a retryable 503 and is NOT
 * negative-cached (KS-OUTAGE). NOT_FOUND vs transient is the whole point — never conflate them.
 */
export function createSecretManagerKeyStore(
  projectId: string,
  client: SecretManagerServiceClient = new SecretManagerServiceClient(),
): PerInstallKeyStore {
  return {
    async getKey(clientId) {
      // Defense-in-depth: the resolver already validated the shape, but never build a resource path
      // from an id we haven't re-checked (no Secret Manager name injection).
      if (!CLIENT_ID_KEY_PATTERN.test(clientId)) return undefined;
      const name = `projects/${projectId}/secrets/${SECRET_NAME_PREFIX}${clientId}/versions/latest`;
      try {
        const [version] = await client.accessSecretVersion({ name });
        const data = version.payload?.data;
        if (data == null) return undefined;
        const value = typeof data === "string" ? data : Buffer.from(data).toString("utf8");
        return value.length > 0 ? value : undefined;
      } catch (err) {
        // NOT_FOUND = unprovisioned/revoked install → fail closed (undefined, negative-cached → 401).
        if ((err as { code?: number }).code === GRPC_NOT_FOUND) return undefined;
        // Anything else = TRANSIENT. Throw so the request becomes a retryable 503 and is NOT cached —
        // a Secret-Manager blip must not lock a legit install out for the cache TTL. Value never logged.
        throw new KeyStoreUnavailableError(`secret_manager_unavailable:${(err as { code?: number }).code ?? "unknown"}`);
      }
    },
  };
}
