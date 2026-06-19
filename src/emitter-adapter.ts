/**
 * OET reference emitter ADAPTER (M4) — the real I/O implementations of the emitter's injected seams.
 *
 * Split from the pure `emitter.ts` core (which is at the SEC gate) so the buffering/retry/consent
 * logic stays runtime-free and testable. These are the thin, swappable bindings a real client wires:
 *   - `createFetchTransport` — POST over `fetch` (Node 20+/browser); a custom `fetch` is injectable.
 *   - `createPersistentClientIdStore` — back the stable id with any Web-Storage-like KV (localStorage,
 *     a file shim, the Windows registry behind the same 2 methods).
 *   - `createMemoryClientIdStore` / `defaultGenId` — convenience for tests and first wiring.
 *
 * No live POST or persisted write happens until a real `fetch`/storage is supplied AND the client is
 * actually run — the OET endpoint deploy + any real traffic still wait for the Owner's GO.
 */

import { randomUUID } from "node:crypto";
import type { EmitterTransport, ClientIdStore } from "./emitter.js";

/** Minimal `fetch` shape we depend on — keeps this typecheck-clean without the DOM lib. */
export type FetchLike = (
  url: string,
  init: { method: string; body: string; headers: Record<string, string> },
) => Promise<{ status: number }>;

/**
 * Wrap `fetch` as an `EmitterTransport`. A network failure rejects (the emitter treats a throw as a
 * transient error and retries); a real HTTP response resolves with its status, which the emitter maps
 * (2xx clear · 429/5xx retry · other 4xx drop). Pass a custom `fetchImpl` for tests or a non-global fetch.
 */
export function createFetchTransport(
  fetchImpl: FetchLike = globalThis.fetch as unknown as FetchLike,
): EmitterTransport {
  return {
    async post(url, body, headers) {
      const res = await fetchImpl(url, { method: "POST", body, headers });
      return { status: res.status };
    },
  };
}

/** A Web-Storage-like key/value sink (localStorage, a file shim, etc.). */
export interface KeyValueStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** Persist the stable client_id in any KV storage. The same 2 methods back localStorage, a file, etc. */
export function createPersistentClientIdStore(
  storage: KeyValueStorage,
  key = "oet_client_id",
): ClientIdStore {
  return {
    load: () => storage.getItem(key),
    save: (id) => storage.setItem(key, id),
  };
}

/** In-memory store — fine for a single process run / tests; not persisted across restarts. */
export function createMemoryClientIdStore(initial: string | null = null): ClientIdStore {
  let value = initial;
  return {
    load: () => value,
    save: (id) => {
      value = id;
    },
  };
}

/** Default GUID generator for a first-run client_id — a vendor-free random UUID (PII-free). */
export function defaultGenId(): string {
  return randomUUID();
}
