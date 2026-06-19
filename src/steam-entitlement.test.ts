import { describe, it, expect, vi } from "vitest";
import { createSteamEntitlementVerifier } from "./steam-entitlement.js";
import type { FetchJson } from "./msstore-live.js";

/** Build a FetchJson that answers by URL substring; records calls. */
function fetcher(routes: { auth?: unknown; own?: unknown; authStatus?: number; ownStatus?: number } = {}) {
  const calls: string[] = [];
  const fetchJson: FetchJson = async (url) => {
    calls.push(url);
    if (url.includes("AuthenticateUserTicket")) {
      return { status: routes.authStatus ?? 200, json: async () => routes.auth ?? { response: { params: { result: "OK", steamid: "7656119" } } } };
    }
    return { status: routes.ownStatus ?? 200, json: async () => routes.own ?? { appownership: { ownsapp: true } } };
  };
  return { fetchJson, calls };
}

const cfg = { getWebApiKey: async () => "PUBLISHER_KEY", appId: "480" };
const TICKET = "deadbeef01";

describe("createSteamEntitlementVerifier (A4 Steam)", () => {
  it("true when the ticket authenticates AND the steamid owns the app", async () => {
    const { fetchJson, calls } = fetcher();
    const verify = createSteamEntitlementVerifier(cfg, fetchJson);
    expect(await verify(TICKET)).toBe(true);
    expect(calls[0]).toContain("AuthenticateUserTicket");
    expect(calls[0]).toContain("appid=480");
    expect(calls[1]).toContain("CheckAppOwnership");
    expect(calls[1]).toContain("steamid=7656119");
  });

  it("false when the user does NOT own the app", async () => {
    const { fetchJson } = fetcher({ own: { appownership: { ownsapp: false } } });
    expect(await createSteamEntitlementVerifier(cfg, fetchJson)(TICKET)).toBe(false);
  });

  it("false when ticket authentication is not OK (forged/expired ticket)", async () => {
    const { fetchJson, calls } = fetcher({ auth: { response: { error: { errorcode: 101 } } } });
    expect(await createSteamEntitlementVerifier(cfg, fetchJson)(TICKET)).toBe(false);
    expect(calls).toHaveLength(1); // never checks ownership without a valid steamid
  });

  it("fails closed on a non-200 from Steam, and on a fetch error", async () => {
    const { fetchJson } = fetcher({ authStatus: 503 });
    expect(await createSteamEntitlementVerifier(cfg, fetchJson)(TICKET)).toBe(false);
    const throwing: FetchJson = async () => { throw new Error("network"); };
    expect(await createSteamEntitlementVerifier(cfg, throwing)(TICKET)).toBe(false);
  });

  it("REJECTS a malformed ticket without calling Steam (no SSRF / no key spend)", async () => {
    const fetchJson = vi.fn<FetchJson>(async () => ({ status: 200, json: async () => ({}) }));
    const verify = createSteamEntitlementVerifier(cfg, fetchJson);
    for (const bad of ["", "not hex!", "../x", "a".repeat(3000)]) {
      expect(await verify(bad)).toBe(false);
    }
    expect(fetchJson).not.toHaveBeenCalled();
  });

  it("never puts the Web API key in a thrown error or return value (secret hygiene)", async () => {
    const { fetchJson } = fetcher({ own: { appownership: { ownsapp: false } } });
    const r = await createSteamEntitlementVerifier({ getWebApiKey: async () => "SUPER_SECRET_KEY", appId: "480" }, fetchJson)(TICKET);
    expect(JSON.stringify(r)).not.toContain("SUPER_SECRET_KEY");
  });
});
