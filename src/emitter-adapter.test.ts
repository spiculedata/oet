import { describe, it, expect, vi } from "vitest";
import {
  createFetchTransport,
  createPersistentClientIdStore,
  defaultGenId,
  type FetchLike,
  type KeyValueStorage,
} from "./emitter-adapter.js";
import { createEmitter } from "./emitter.js";
import { validateEnvelope } from "./validate.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

describe("createFetchTransport", () => {
  it("POSTs body + headers to the URL and returns the status", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => ({ status: 202 }));
    const t = createFetchTransport(fetchImpl);
    const r = await t.post("https://x/ingest", '{"a":1}', { "content-type": "application/json" });
    expect(r).toEqual({ status: 202 });
    expect(fetchImpl).toHaveBeenCalledWith("https://x/ingest", {
      method: "POST",
      body: '{"a":1}',
      headers: { "content-type": "application/json" },
    });
  });

  it("propagates a network failure as a throw (emitter treats it as transient)", async () => {
    const t = createFetchTransport(async () => { throw new Error("offline"); });
    await expect(t.post("u", "b", {})).rejects.toThrow("offline");
  });
});

describe("createPersistentClientIdStore", () => {
  function fakeStorage(): KeyValueStorage & { map: Map<string, string> } {
    const map = new Map<string, string>();
    return { map, getItem: (k) => map.get(k) ?? null, setItem: (k, v) => void map.set(k, v) };
  }

  it("reads/writes the id under the configured key", () => {
    const storage = fakeStorage();
    const store = createPersistentClientIdStore(storage);
    expect(store.load()).toBeNull();
    store.save("windows-abc");
    expect(storage.map.get("oet_client_id")).toBe("windows-abc");
    expect(store.load()).toBe("windows-abc");
  });

  it("survives a 'restart': a new store over the same storage reuses the id", () => {
    const storage = fakeStorage();
    createPersistentClientIdStore(storage).save("windows-keep");
    expect(createPersistentClientIdStore(storage).load()).toBe("windows-keep");
  });
});

describe("defaultGenId", () => {
  it("returns a vendor-free UUID-shaped id", () => {
    expect(defaultGenId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });
});

describe("emitter + adapter — wired end to end (mock fetch)", () => {
  it("persists the id across runs and POSTs a spec-valid envelope", async () => {
    const storage = new Map<string, string>();
    const kv: KeyValueStorage = { getItem: (k) => storage.get(k) ?? null, setItem: (k, v) => void storage.set(k, v) };
    const posted: string[] = [];
    const fetchImpl: FetchLike = async (_u, init) => { posted.push(init.body); return { status: 202 }; };

    const base = {
      endpoint: "https://x/ingest",
      platform: "windows",
      appVersion: "2.2.0+27",
      consent: true,
      now: () => 1_700_000_000_000,
      transport: createFetchTransport(fetchImpl),
      genId: () => "fixed-guid",
    };

    const e1 = createEmitter({ ...base, store: createPersistentClientIdStore(kv) });
    e1.track("app_open");
    await e1.flush();

    // A "second run" reuses the persisted id (no regeneration).
    const e2 = createEmitter({ ...base, store: createPersistentClientIdStore(kv) });
    expect(e2.clientId).toBe("windows-fixed-guid");

    const body = JSON.parse(posted[0]!);
    expect(validateEnvelope(body, DEFAULT_ALLOWLIST).ok).toBe(true);
    expect(body.client_id).toBe("windows-fixed-guid");
  });
});
