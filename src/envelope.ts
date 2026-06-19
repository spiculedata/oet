/**
 * OET — Open Event Telemetry
 * The `oet.event.v1` envelope: the single, versioned contract every client POSTs.
 *
 * DOMAIN LAWS encoded here:
 *  - PII-free: client_id is a stable-per-install, vendor-free GUID; user_id is optional
 *    and only set when a user is signed in. No emails, names, IPs, or device fingerprints.
 *  - Opt-in consent: `consent` must be true for the server to retain the events.
 *  - GA4-shaped destination: events normalize to GA4 events_* columns downstream
 *    (event_params, user_pseudo_id, platform, event_timestamp) so a single UNION ALL
 *    view stitches OET alongside a first-party GA4 export.
 */

export const ENVELOPE_VERSION = "oet.event.v1" as const;

/**
 * §2.4 registered `platform` tokens (v0.1). `platform` is a stored, queryable dimension that is
 * NOT allowlisted, so it MUST be a member of this closed set — a format-only check would let a
 * well-formed `platform:"zzz"` poison the platform breakdown (DOMAIN LAW 3/4; SEC C6/R1). New
 * tokens are added by spec revision, never invented ad-hoc by clients.
 */
export const REGISTERED_PLATFORMS: ReadonlySet<string> = new Set([
  "android",
  "ios",
  "web",
  "macos",
  "windows",
  "linux",
  "steam",
  "cli",
  "embedded",
  "server",
]);

/** A single event param value — GA4 supports string/int/double; we mirror that. */
export type ParamValue = string | number | boolean | null;

export interface OetEvent {
  /** Event name — must be on the server-side allowlist or it is dropped. */
  name: string;
  /** Client-side ISO-8601 timestamp; the server stamps an authoritative receive time too. */
  ts: string;
  /** Flat key/value params. Keep PII-free. */
  params?: Record<string, ParamValue>;
}

export interface OetEnvelope {
  /** Stable per-install GUID, generated first-run. PII-free. e.g. "win-<guid>". */
  client_id: string;
  /** Optional signed-in user id. null when anonymous. */
  user_id: string | null;
  /** The dimension first-party SDKs can't give you: "windows" | "linux" | "steam" | ... */
  platform: string;
  /** Semver+build, e.g. "2.2.0+27". */
  app_version: string;
  /** Telemetry is opt-in; respected server-side. */
  consent: boolean;
  /**
   * REQUIRED (v0.1.1, §5.5). ISO-8601+tz time the client built/sent this batch. Signed (part of the
   * canonical payload), so the server can enforce replay freshness: it must fall within an asymmetric
   * window around the server receive time (§5.4). The same value is reused on a transport retry of the
   * same batch so the freshness anchor and nonce don't shift.
   */
  sent_at: string;
  /** Batch of events in this flush. */
  events: OetEvent[];
  /** hmac-sha256 over the canonical payload — authenticity / anti-abuse. */
  sig?: string;
}
