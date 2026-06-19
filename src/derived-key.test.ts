import { describe, it, expect, vi } from "vitest";
import {
  deriveClientKey,
  createDerivedKeyStore,
  createInMemoryRevocationList,
} from "./derived-key.js";
import { KeyStoreUnavailableError } from "./ingest.js";

const ROOT = Buffer.from("a-256-bit-root-key-held-in-secret-manager-xx", "utf8");

describe("deriveClientKey (A3 — HKDF per-install keys, proposed)", () => {
  it("is deterministic — same (root, clientId, version) → same key", () => {
    expect(deriveClientKey("inst_abc", ROOT)).toBe(deriveClientKey("inst_abc", ROOT));
  });
  it("derives DISTINCT keys per client_id", () => {
    expect(deriveClientKey("inst_a", ROOT)).not.toBe(deriveClientKey("inst_b", ROOT));
  });
  it("derives DISTINCT keys per root key (rotating the root invalidates all)", () => {
    const other = Buffer.from("a-DIFFERENT-256-bit-root-key-secret-manager-y", "utf8");
    expect(deriveClientKey("inst_a", ROOT)).not.toBe(deriveClientKey("inst_a", other));
  });
  it("derives DISTINCT keys per keyVersion (the rotation lever)", () => {
    expect(deriveClientKey("inst_a", ROOT, "v1")).not.toBe(deriveClientKey("inst_a", ROOT, "v2"));
  });
  it("produces a 256-bit base64 secret", () => {
    const k = deriveClientKey("inst_a", ROOT);
    expect(Buffer.from(k, "base64")).toHaveLength(32);
  });
  it("accepts a string or Buffer root key equivalently", () => {
    expect(deriveClientKey("inst_a", "root-str")).toBe(deriveClientKey("inst_a", Buffer.from("root-str", "utf8")));
  });
});

describe("createDerivedKeyStore (DK1–DK4 — verify-side)", () => {
  it("getKey derives the same key deriveClientKey would (drop-in PerInstallKeyStore)", async () => {
    const store = createDerivedKeyStore({ getRootKey: () => ROOT });
    expect(await store.getKey("inst_a")).toBe(deriveClientKey("inst_a", ROOT, "v1"));
  });

  it("honors keyVersion (DK3 rotation lever)", async () => {
    const store = createDerivedKeyStore({ getRootKey: () => ROOT, keyVersion: "v2" });
    expect(await store.getKey("inst_a")).toBe(deriveClientKey("inst_a", ROOT, "v2"));
  });

  it("DK2: a revoked client_id resolves to undefined (→ 401), and is derivable again once restored", async () => {
    const deny = createInMemoryRevocationList(["inst_bad"]);
    const store = createDerivedKeyStore({ getRootKey: () => ROOT, revocationList: deny });
    expect(await store.getKey("inst_bad")).toBeUndefined();
    expect(await store.getKey("inst_ok")).toBe(deriveClientKey("inst_ok", ROOT, "v1"));
    deny.restore("inst_bad");
    expect(await store.getKey("inst_bad")).toBe(deriveClientKey("inst_bad", ROOT, "v1"));
  });

  it("DK2 fail-closed: a deny-list OUTAGE propagates (KeyStoreUnavailableError → 503), never accepts", async () => {
    const store = createDerivedKeyStore({
      getRootKey: () => ROOT,
      revocationList: { isRevoked: () => { throw new KeyStoreUnavailableError("denylist_down"); } },
    });
    await expect(store.getKey("inst_a")).rejects.toBeInstanceOf(KeyStoreUnavailableError);
  });

  it("DK1 fail-closed: a root-key fetch fault propagates (→ 503), never derives a wrong key", async () => {
    const store = createDerivedKeyStore({
      getRootKey: () => { throw new KeyStoreUnavailableError("root_unavailable"); },
    });
    await expect(store.getKey("inst_a")).rejects.toBeInstanceOf(KeyStoreUnavailableError);
  });

  it("checks revocation BEFORE fetching the root key (no derive work on a revoked id)", async () => {
    const getRootKey = vi.fn(() => ROOT);
    const store = createDerivedKeyStore({ getRootKey, revocationList: createInMemoryRevocationList(["inst_bad"]) });
    await store.getKey("inst_bad");
    expect(getRootKey).not.toHaveBeenCalled();
  });
});
