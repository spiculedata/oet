import { describe, it, expect, vi } from "vitest";
import {
  createAzureAdTokenIssuer,
  createMsStoreAcquisitionSource,
  type FetchJson,
} from "./msstore-live.js";
import { runAcquisitionPull } from "./msstore-puller.js";

/** Build a FetchJson stub from a (url, init) → { status, body } handler. */
function stub(handler: (url: string, init: { method: string; headers: Record<string, string>; body?: string }) => { status: number; body: unknown }): { fetchJson: FetchJson; calls: { url: string; init: { method: string; headers: Record<string, string>; body?: string } }[] } {
  const calls: { url: string; init: { method: string; headers: Record<string, string>; body?: string } }[] = [];
  const fetchJson: FetchJson = async (url, init) => {
    calls.push({ url, init });
    const { status, body } = handler(url, init);
    return { status, json: async () => body };
  };
  return { fetchJson, calls };
}

const AZURE = {
  tokenEndpoint: "https://login.microsoftonline.com/tenant-x/oauth2/token",
  clientId: "app-client-id",
  getClientSecret: async () => "super-secret",
  resource: "https://manage.devcenter.microsoft.com",
};

describe("createAzureAdTokenIssuer — Azure AD client-credentials", () => {
  it("POSTs the client-credentials grant and returns the access token", async () => {
    const { fetchJson, calls } = stub(() => ({ status: 200, body: { access_token: "tok-123", expires_in: 3600 } }));
    const issue = createAzureAdTokenIssuer(AZURE, fetchJson, () => 1000);
    expect(await issue()).toBe("tok-123");
    const body = calls[0]!.init.body!;
    expect(body).toContain("grant_type=client_credentials");
    expect(body).toContain("client_id=app-client-id");
    expect(body).toContain("client_secret=super-secret");
    expect(body).toContain(encodeURIComponent("https://manage.devcenter.microsoft.com"));
  });

  it("caches the token until ~1 min before expiry, then re-issues", async () => {
    let t = 0;
    const fetchSpy = vi.fn(async () => ({ status: 200, json: async () => ({ access_token: `tok-${t}`, expires_in: 3600 }) }));
    const issue = createAzureAdTokenIssuer(AZURE, fetchSpy as unknown as FetchJson, () => t);
    expect(await issue()).toBe("tok-0");
    t = 60_000; // still inside the window
    expect(await issue()).toBe("tok-0"); // cached
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    t = 3600_000; // past expiry
    expect(await issue()).toBe("tok-3600000");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("throws on a non-200 or a missing token", async () => {
    const fail = createAzureAdTokenIssuer(AZURE, stub(() => ({ status: 401, body: {} })).fetchJson);
    await expect(fail()).rejects.toThrow(/azure_ad_token_failed:401/);
    const empty = createAzureAdTokenIssuer(AZURE, stub(() => ({ status: 200, body: {} })).fetchJson);
    await expect(empty()).rejects.toThrow(/azure_ad_token_missing/);
  });
});

// A recorded-fixture acquisitions response (Partner Center shape). Includes PII fields (ageGroup/gender)
// that MUST be dropped, plus a `@nextLink` to exercise pagination.
const PAGE_1 = {
  Value: [
    { date: "2026-06-18", applicationId: "9ND80M1TT3JH", acquisitionType: "Free", ageGroup: "25-34", gender: "m", market: "US", osVersion: "Windows 11", deviceType: "PC", storeClient: "Storefront", acquisitionQuantity: 123 },
    { date: "2026-06-18", acquisitionType: "Paid", market: "GB", deviceType: "PC", acquisitionQuantity: 7 },
  ],
  "@nextLink": "/v1.0/my/analytics/acquisitions?applicationId=9ND80M1TT3JH&skip=2",
};
const PAGE_2 = {
  Value: [{ date: "2026-06-18", acquisitionType: "Trial", market: "DE", acquisitionQuantity: 4 }],
};

describe("createMsStoreAcquisitionSource — live acquisitions report", () => {
  function source(pages: { status: number; body: unknown }[]) {
    let i = 0;
    return stub(() => pages[Math.min(i++, pages.length - 1)]!);
  }

  it("sends a Bearer token, maps rows, and DROPS demographic PII (ageGroup/gender)", async () => {
    const { fetchJson, calls } = source([{ status: 200, body: PAGE_2 }]); // single page
    const src = createMsStoreAcquisitionSource({ productId: "9ND80M1TT3JH", getToken: async () => "tok-xyz" }, fetchJson);
    const rows = await src.fetch("2026-06-18", "2026-06-18");
    expect(calls[0]!.init.headers.authorization).toBe("Bearer tok-xyz");
    expect(calls[0]!.url).toContain("applicationId=9ND80M1TT3JH");
    expect(rows).toEqual([{ date: "2026-06-18", acquisitionType: "Trial", market: "DE", acquisitionQuantity: 4 }]);
  });

  it("follows @nextLink pagination and concatenates pages", async () => {
    const { fetchJson, calls } = source([{ status: 200, body: PAGE_1 }, { status: 200, body: PAGE_2 }]);
    const src = createMsStoreAcquisitionSource({ productId: "9ND80M1TT3JH", getToken: async () => "t" }, fetchJson);
    const rows = await src.fetch("2026-06-18", "2026-06-18");
    expect(calls).toHaveLength(2); // page 1 + the @nextLink page
    expect(calls[1]!.url).toContain("skip=2");
    expect(rows.map((r) => r.market)).toEqual(["US", "GB", "DE"]);
    // PII never carried through:
    expect(JSON.stringify(rows)).not.toMatch(/ageGroup|gender|25-34/);
  });

  it("throws on a non-200 acquisitions response", async () => {
    const { fetchJson } = source([{ status: 403, body: {} }]);
    const src = createMsStoreAcquisitionSource({ productId: "x", getToken: async () => "t" }, fetchJson);
    await expect(src.fetch("2026-06-18", "2026-06-18")).rejects.toThrow(/msstore_acquisitions_failed:403/);
  });

  it("GL-SSRF: REFUSES an @nextLink to a different host (no SSRF / no token leak)", async () => {
    const evil = { Value: [{ date: "2026-06-18", market: "US", acquisitionQuantity: 1 }], "@nextLink": "https://evil.example/steal" };
    const { fetchJson, calls } = source([{ status: 200, body: evil }]);
    const src = createMsStoreAcquisitionSource({ productId: "x", getToken: async () => "secret-token" }, fetchJson);
    await expect(src.fetch("2026-06-18", "2026-06-18")).rejects.toThrow(/msstore_nextlink_host_mismatch:https:\/\/evil\.example/);
    expect(calls).toHaveLength(1); // never followed the off-host link → token never sent to evil.example
  });

  it("GL-SSRF: REFUSES a same-host https→http DOWNGRADE @nextLink (token never sent over cleartext)", async () => {
    // same host as the default base, but http:// — a host-only check would have passed this and leaked
    // the Bearer token over plaintext. The origin check (scheme+host+port) + https requirement refuses it.
    const downgrade = { Value: [{ date: "2026-06-18", market: "US", acquisitionQuantity: 1 }], "@nextLink": "http://manage.devcenter.microsoft.com/page2" };
    const { fetchJson, calls } = source([{ status: 200, body: downgrade }]);
    const src = createMsStoreAcquisitionSource({ productId: "x", getToken: async () => "secret-token" }, fetchJson);
    await expect(src.fetch("2026-06-18", "2026-06-18")).rejects.toThrow(/msstore_nextlink_host_mismatch:http:\/\/manage\.devcenter\.microsoft\.com/);
    expect(calls).toHaveLength(1); // never followed the downgraded link
  });

  it("GL-SSRF: FOLLOWS a legitimate same-origin @nextLink (relative + absolute https same host)", async () => {
    const page1 = { Value: [{ date: "2026-06-18", market: "US", acquisitionQuantity: 1 }], "@nextLink": "/v1.0/my/analytics/acquisitions?token=p2" };
    const page2 = { Value: [{ date: "2026-06-18", market: "GB", acquisitionQuantity: 2 }], "@nextLink": "https://manage.devcenter.microsoft.com/v1.0/my/analytics/acquisitions?token=p3" };
    const page3 = { Value: [{ date: "2026-06-18", market: "DE", acquisitionQuantity: 3 }] };
    const { fetchJson, calls } = source([{ status: 200, body: page1 }, { status: 200, body: page2 }, { status: 200, body: page3 }]);
    const src = createMsStoreAcquisitionSource({ productId: "x", getToken: async () => "t" }, fetchJson);
    const rows = await src.fetch("2026-06-18", "2026-06-18");
    expect(rows).toHaveLength(3);
    expect(calls).toHaveLength(3); // followed both same-origin links
  });
});

describe("GL1 end-to-end — live source → runAcquisitionPull → GA4 rows", () => {
  it("normalizes the live acquisitions into allowlisted GA4 rows (aggregate-correct)", async () => {
    const { fetchJson } = (() => {
      let i = 0;
      const pages = [{ status: 200, body: PAGE_1 }, { status: 200, body: PAGE_2 }];
      return stub(() => pages[Math.min(i++, pages.length - 1)]!);
    })();
    const source = createMsStoreAcquisitionSource({ productId: "9ND80M1TT3JH", getToken: async () => "t" }, fetchJson);
    const bqInsert = vi.fn();
    const res = await runAcquisitionPull("2026-06-18", "2026-06-18", { source, bqInsert });
    expect(res).toEqual({ fetched: 3, written: 3, skipped: 0 });
    const rows = bqInsert.mock.calls[0]![0];
    expect(rows.every((r: { event_name: string }) => r.event_name === "store_download")).toBe(true);
    // count carried as a param, never exploded into per-user events (LAW 6)
    const q = rows[0].event_params.find((p: { key: string }) => p.key === "acquisition_quantity");
    expect(q.value).toEqual({ int_value: 123 });
  });
});
