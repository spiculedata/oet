/**
 * OET reference emitter (Spec §1 "Emitter", M4) — the canonical client that builds and POSTs
 * `oet.event.v1` envelopes. Language-agnostic in spirit; this is the TypeScript reference that a
 * Windows/Steam/CLI client adapts. It closes the loop: emitter → ingestion endpoint → GA4 table.
 *
 * Pure + injected I/O: the HTTP transport, the clock, the stable-id store, and the HMAC signer are
 * all injected, so the buffering/retry/consent logic is unit-testable with no network, no real
 * clock, and no crypto in the core. `makeHmacSigner` (below) is the client counterpart to the
 * server's verifier — both canonicalize identically (§5.2), so a signed envelope verifies.
 *
 * DOMAIN LAWS the emitter upholds client-side:
 *  - PII-free (LAW 1): `client_id` is a vendor-free random GUID, stable per install; no email/name/
 *    hardware id ever enters the envelope.
 *  - Opt-in consent (LAW 2): with consent !== true the emitter collects and sends NOTHING — lawful
 *    by design, not just server-enforced. (The server still enforces it independently.)
 *  - GA4-shaped contract (LAW 5): the envelope it builds is exactly what `validateEnvelope` accepts.
 */

import { createHmac } from "node:crypto";
import { canonicalEnvelope } from "./canonical.js";
import { MAX_EVENTS_PER_BATCH } from "./validate.js";
import type { ParamValue } from "./envelope.js";

export interface EmitterTransport {
  /** POST the body; resolve with the HTTP status, or reject/throw on a network failure. */
  post(url: string, body: string, headers: Record<string, string>): Promise<{ status: number }>;
}

/** Persists the stable per-install client_id across runs (real: a file/registry/localStorage). */
export interface ClientIdStore {
  load(): string | null;
  save(id: string): void;
}

export interface EmitterConfig {
  endpoint: string;
  platform: string;
  appVersion: string;
  /** Opt-in. With anything other than true, the emitter collects and sends nothing. */
  consent: boolean;
  userId?: string | null;
  transport: EmitterTransport;
  /** Server-authoritative-ish client clock, epoch ms (advisory `ts`; server re-stamps, §2.5). */
  now: () => number;
  store: ClientIdStore;
  /** Generate a fresh GUID for a first-run client_id. Default: crypto.randomUUID via the adapter. */
  genId: () => string;
  /** Sign the envelope → the `sig` value. Omit for an App Check deployment (set appCheckToken). */
  sign?: (envelope: Record<string, unknown>) => string;
  appCheckToken?: string;
  maxRetries?: number; // transient retries per chunk, default 3
  maxBatch?: number; // events per envelope, default MAX_EVENTS_PER_BATCH (1000)
}

export interface FlushResult {
  sent: number;
  remaining: number;
  ok: boolean;
}

export interface Emitter {
  readonly clientId: string;
  /** Buffer one event (no-op without consent). */
  track(name: string, params?: Record<string, ParamValue>): void;
  /** Build → sign → POST buffered events in ≤maxBatch chunks, with bounded transient retry. */
  flush(): Promise<FlushResult>;
  /** Count of buffered, not-yet-sent events. */
  pending(): number;
}

interface BufferedEvent {
  name: string;
  ts: string;
  params?: Record<string, ParamValue>;
}

const isRetryable = (status: number): boolean => status === 429 || status >= 500;

export function createEmitter(config: EmitterConfig): Emitter {
  const maxRetries = config.maxRetries ?? 3;
  const maxBatch = Math.min(config.maxBatch ?? MAX_EVENTS_PER_BATCH, MAX_EVENTS_PER_BATCH);
  const consented = config.consent === true;

  // Stable per-install client_id: load it, or mint a vendor-free `<platform>-<guid>` once and persist.
  let clientId = config.store.load();
  if (clientId === null) {
    clientId = `${config.platform}-${config.genId()}`;
    config.store.save(clientId);
  }

  const buffer: BufferedEvent[] = [];

  function buildEnvelope(events: BufferedEvent[]): Record<string, unknown> {
    const envelope: Record<string, unknown> = {
      client_id: clientId,
      user_id: config.userId ?? null,
      platform: config.platform,
      app_version: config.appVersion,
      consent: true, // only ever built when consented
      // §5.5: stamped once per chunk here (buildEnvelope runs before the retry loop), so a transport
      // retry of the same batch re-sends the identical sent_at — the freshness anchor + sig don't shift.
      sent_at: new Date(config.now()).toISOString(),
      events,
    };
    if (config.sign) envelope.sig = config.sign(envelope);
    return envelope;
  }

  /** Returns 'sent' on 2xx, 'drop' on a non-retryable 4xx, 'keep' if transient retries are exhausted. */
  async function postChunk(events: BufferedEvent[]): Promise<"sent" | "drop" | "keep"> {
    const body = JSON.stringify(buildEnvelope(events));
    const headers: Record<string, string> = { "content-type": "application/json; charset=utf-8" };
    if (config.appCheckToken !== undefined) headers["x-firebase-appcheck"] = config.appCheckToken;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      let status: number;
      try {
        ({ status } = await config.transport.post(config.endpoint, body, headers));
      } catch {
        continue; // network failure → transient, retry
      }
      if (status >= 200 && status < 300) return "sent";
      if (!isRetryable(status)) return "drop"; // 400/401/413 won't succeed on resend
      // retryable (429/5xx) → loop
    }
    return "keep"; // exhausted transient retries — keep for the next flush (no data loss)
  }

  return {
    get clientId() {
      return clientId as string;
    },
    track(name, params) {
      if (!consented) return; // LAW 2: collect nothing without consent
      const event: BufferedEvent = { name, ts: new Date(config.now()).toISOString() };
      if (params !== undefined) event.params = params;
      buffer.push(event);
    },
    async flush() {
      if (!consented) return { sent: 0, remaining: 0, ok: true };
      let sent = 0;
      while (buffer.length > 0) {
        const chunk = buffer.slice(0, maxBatch);
        const outcome = await postChunk(chunk);
        if (outcome === "keep") break; // transient — stop, retain the buffer, try again later
        buffer.splice(0, chunk.length); // 'sent' or 'drop' both remove the chunk
        if (outcome === "sent") sent += chunk.length;
      }
      return { sent, remaining: buffer.length, ok: buffer.length === 0 };
    },
    pending() {
      return buffer.length;
    },
  };
}

/**
 * Client-side HMAC signer — the counterpart to the server's `makeHmacVerifier`. Signs the §5.2
 * canonical payload (envelope minus `sig`), so the server, recomputing the same canonical bytes,
 * verifies the signature. Kept here (uses crypto) so `createEmitter` can stay crypto-free.
 */
export function makeHmacSigner(secret: string): (envelope: Record<string, unknown>) => string {
  return (envelope) => {
    const mac = createHmac("sha256", secret).update(canonicalEnvelope(envelope)).digest("base64");
    return `hmac-sha256:${mac}`;
  };
}
