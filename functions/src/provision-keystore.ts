/**
 * RP2 — real per-install key PROVISIONER backed by **Secret Manager** (the write side of GL3's keystore).
 *
 * `create(clientId, key)` is **atomic create-if-absent**: it creates the secret `oet-client-<client_id>`
 * (Secret Manager's `createSecret` is atomic and fails `ALREADY_EXISTS` if the id is taken → `"exists"`,
 * which the core turns into a regenerate), then adds the key as the first version. It NEVER overwrites or
 * returns an existing secret (no exfil / no clobber). A transient fault throws `KeyStoreUnavailableError`
 * (→ retryable 503), never a silent/partial mint. The key value is never logged (DOMAIN LAW 7).
 *
 * Least-priv (RP5): the provisioner SA needs `secretmanager.admin`-equivalent **scoped to `oet-client-*`**
 * (create + addVersion) — a broader, SEPARATE grant from the ingest reader's `secretAccessor`. See
 * deploy/RUNBOOK.md.
 */
import { SecretManagerServiceClient } from "@google-cloud/secret-manager";
import { CLIENT_ID_KEY_PATTERN, KeyStoreUnavailableError, type KeyProvisioner } from "oet";

const SECRET_NAME_PREFIX = "oet-client-";
/** gRPC ALREADY_EXISTS — the secret id is already taken (the core then regenerates a fresh id). */
const GRPC_ALREADY_EXISTS = 6;

export function createSecretManagerKeyProvisioner(
  projectId: string,
  client: SecretManagerServiceClient = new SecretManagerServiceClient(),
): KeyProvisioner {
  const parent = `projects/${projectId}`;
  return {
    async create(clientId, key) {
      // Defense-in-depth: never build a Secret Manager resource id from an unvalidated client_id, even
      // though the core only ever passes ids it generated to CLIENT_ID_KEY_PATTERN.
      if (!CLIENT_ID_KEY_PATTERN.test(clientId)) {
        throw new KeyStoreUnavailableError("provision_invalid_client_id");
      }
      const secretId = `${SECRET_NAME_PREFIX}${clientId}`;
      try {
        // 1. atomic create — fails ALREADY_EXISTS if the id is taken (→ "exists", no overwrite).
        await client.createSecret({
          parent,
          secretId,
          secret: { replication: { automatic: {} } },
        });
      } catch (err) {
        if ((err as { code?: number }).code === GRPC_ALREADY_EXISTS) return "exists";
        throw new KeyStoreUnavailableError(`secret_manager_create_unavailable:${(err as { code?: number }).code ?? "unknown"}`);
      }
      try {
        // 2. add the key as the secret's first version. (We just created the secret, so this is the
        // first version; a failure here is transient → retryable. The empty secret with no version is
        // inert — the ingest reader treats "no version" as unprovisioned/fail-closed.)
        await client.addSecretVersion({
          parent: `${parent}/secrets/${secretId}`,
          payload: { data: Buffer.from(key, "utf8") },
        });
      } catch (err) {
        throw new KeyStoreUnavailableError(`secret_manager_addversion_unavailable:${(err as { code?: number }).code ?? "unknown"}`);
      }
      return "created";
    },
  };
}
