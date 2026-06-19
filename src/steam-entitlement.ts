/**
 * A4 / Steam entitlement — server-side ownership check for the Steam channel (Owner-required; SEC gate).
 *
 * The desktop PoW (PW1–PW4) raises the cost of scripted minting; on the **Steam channel** the Owner also
 * requires a real **proof of ownership**. This verifier validates a Steam **session ticket** server-side
 * via the Steam Web API (publisher key) and confirms the user owns the app — **no client-trusted flag**:
 *   1. `ISteamUserAuth/AuthenticateUserTicket` — proves the ticket is genuine and yields the `steamid`;
 *   2. `ISteamUser/CheckAppOwnership` — confirms that `steamid` owns `appId`.
 * Fail CLOSED on any non-OK result, non-200, parse problem, or error. The Web API key is INJECTED
 * (real: Secret Manager) and **never logged**; the fixed `partner.steam-api.com` host + URL-encoded params
 * mean there's no SSRF surface. Pure: `node:crypto`-free, an injected `FetchJson` does all I/O.
 */
import type { FetchJson } from "./msstore-live.js";

export interface SteamEntitlementConfig {
  /** Steam publisher **Web API key** (real: Secret Manager). Never logged. */
  getWebApiKey: () => string | Promise<string>;
  /** The Steam appid the install must own. */
  appId: string;
  /** Publisher API base; default `https://partner.steam-api.com`. */
  baseUrl?: string;
}

/** A session ticket is a hex blob; reject anything else before it reaches the URL (defense-in-depth). */
const TICKET_RE = /^[0-9a-fA-F]{1,2048}$/;

/**
 * Build the `verifyEntitlement` dep: `(ticket) => Promise<boolean>` — true only if the ticket authenticates
 * AND the resolved `steamid` owns `appId`. Any failure → false (fail closed).
 */
export function createSteamEntitlementVerifier(
  cfg: SteamEntitlementConfig,
  fetchJson: FetchJson,
): (ticket: string) => Promise<boolean> {
  const base = cfg.baseUrl ?? "https://partner.steam-api.com";
  const get = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await fetchJson(`${base}${path}`, { method: "GET", headers: { accept: "application/json" } });
    if (res.status !== 200) return null;
    const data = await res.json();
    return data !== null && typeof data === "object" ? (data as Record<string, unknown>) : null;
  };
  return async (ticket) => {
    try {
      if (!TICKET_RE.test(ticket)) return false; // malformed → never trusted, never sent
      const key = encodeURIComponent(await cfg.getWebApiKey());
      const appId = encodeURIComponent(cfg.appId);
      // 1. authenticate the ticket → steamid
      const auth = await get(
        `/ISteamUserAuth/AuthenticateUserTicket/v1/?key=${key}&appid=${appId}&ticket=${encodeURIComponent(ticket)}`,
      );
      const params = (auth?.response as { params?: { result?: string; steamid?: string } } | undefined)?.params;
      if (!params || params.result !== "OK" || typeof params.steamid !== "string") return false;
      // 2. confirm ownership of the app
      const own = await get(
        `/ISteamUser/CheckAppOwnership/v3/?key=${key}&steamid=${encodeURIComponent(params.steamid)}&appid=${appId}`,
      );
      const ownership = (own?.appownership as { ownsapp?: boolean } | undefined);
      return ownership?.ownsapp === true;
    } catch {
      return false; // any error (network/parse/etc) → fail closed
    }
  };
}
