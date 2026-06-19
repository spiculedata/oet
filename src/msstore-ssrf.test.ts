/**
 * QA — GL-SSRF: the MS Store live source must not follow a foreign or downgraded `@nextLink` (SEC +
 * automated review, HIGH). GL1 `66d28b6` host-checks the resolved `@nextLink` against the configured
 * base **origin** AND requires **https**, throwing otherwise — so a poisoned link can neither SSRF-pivot
 * nor exfiltrate the Bearer token (not to a foreign host, not over a same-host cleartext downgrade).
 *
 * QA acceptance for the fix:
 *   1. a foreign-host `@nextLink` → throws, foreign host NEVER fetched, token never sent off-host;
 *   2. a same-host (relative) `@nextLink` is still followed — pagination unbroken;
 *   3. a same-host `https→http` DOWNGRADE → REFUSED (origin+https check; was the `.host`-only residual,
 *      now closed — the token never leaves over cleartext http).
 */
import { describe, it, expect } from "vitest";
import { createMsStoreAcquisitionSource, type FetchJson } from "./msstore-live.js";

const MS = "https://manage.devcenter.microsoft.com";
const TOKEN = "BEARER-SECRET-TOKEN";

/** A fetch stub whose page-1 `@nextLink` is caller-chosen; records (host, protocol, token-sent) per call. */
function stubWithNextLink(nextLink: string): { fetchJson: FetchJson; calls: { host: string; protocol: string; sentToken: boolean }[] } {
  const calls: { host: string; protocol: string; sentToken: boolean }[] = [];
  const fetchJson: FetchJson = async (url, init) => {
    const auth = (init.headers as Record<string, string>)?.authorization ?? "";
    const u = new URL(url);
    calls.push({ host: u.host, protocol: u.protocol, sentToken: auth.includes(TOKEN) });
    if (calls.length === 1) {
      return { status: 200, json: async () => ({ Value: [{ date: "2026-06-01", market: "US", acquisitionQuantity: 5 }], "@nextLink": nextLink }) };
    }
    return { status: 200, json: async () => ({ Value: [] }) };
  };
  return { fetchJson, calls };
}
const source = (fetchJson: FetchJson) => createMsStoreAcquisitionSource({ productId: "APP1", baseUrl: MS, getToken: async () => TOKEN }, fetchJson);

describe("GL-SSRF — @nextLink origin+https check (fix proven)", () => {
  it("a foreign-host @nextLink is REFUSED: throws, foreign host never fetched, token never sent off-host", async () => {
    const { fetchJson, calls } = stubWithNextLink("https://evil.example/exfil?skip=1");
    await expect(source(fetchJson).fetch("2026-06-01", "2026-06-02")).rejects.toThrow(/msstore_nextlink_host_mismatch/);
    expect(calls.some((c) => c.host === "evil.example")).toBe(false);
    expect(calls.every((c) => c.host === "manage.devcenter.microsoft.com")).toBe(true);
  });

  it("a same-host relative @nextLink is still followed (pagination unbroken)", async () => {
    const { fetchJson, calls } = stubWithNextLink("/v1.0/my/analytics/acquisitions?skip=1");
    await source(fetchJson).fetch("2026-06-01", "2026-06-02");
    expect(calls).toHaveLength(2);
    expect(calls.every((c) => c.host === "manage.devcenter.microsoft.com" && c.protocol === "https:")).toBe(true);
  });

  it("a same-host https→http DOWNGRADE @nextLink is REFUSED (origin+https — residual CLOSED)", async () => {
    const { fetchJson, calls } = stubWithNextLink("http://manage.devcenter.microsoft.com/v1.0/x?skip=1");
    await expect(source(fetchJson).fetch("2026-06-01", "2026-06-02")).rejects.toThrow(/msstore_nextlink_host_mismatch/);
    expect(calls).toHaveLength(1); // the downgrade leg is never followed…
    expect(calls.some((c) => c.protocol === "http:")).toBe(false); // …so the token never goes over cleartext http
  });
});
