/**
 * OET reference implementation — public entrypoint.
 *
 * This skeleton exposes the pure, testable core (envelope + validation). The serverless
 * ingestion handler (HMAC verify → rate limit → validate → stamp → BigQuery streaming
 * insert) is milestone 2; see the spec in docs/ and the SEC threat model on the board.
 */

export { ENVELOPE_VERSION } from "./envelope.js";
export type { OetEnvelope, OetEvent, ParamValue } from "./envelope.js";
export { validateEnvelope, isEnvelope } from "./validate.js";
export type { ValidationResult } from "./validate.js";
export { toGa4Row, toGa4Rows, paramToGa4Value } from "./ga4.js";
export type {
  Ga4Row,
  Ga4Param,
  Ga4ParamValue,
  Ga4Geo,
  EnrichmentContext,
} from "./ga4.js";
export { canonicalize, canonicalEnvelope } from "./canonical.js";
export { handleIngest, MAX_BODY_BYTES, REPLAY_WINDOW_MS } from "./ingest.js";
export type {
  IngestDeps,
  IngestRequest,
  IngestResponse,
  RateLimiter,
  ReplayCache,
  IpRateGate,
  SecurityEvent,
} from "./ingest.js";
export {
  makeHmacVerifier,
  createInMemoryReplayCache,
  createInMemoryRateLimiter,
  createInMemoryIpRateGate,
  createCoarseGeo,
  makeBqInsert,
  rowInsertId,
  createIngestHttpHandler,
} from "./ingest-adapter.js";
export type {
  SecretLookup,
  RateLimitOptions,
  GeoOptions,
  BqWriter,
  RawHttpRequest,
  HttpResult,
  AdapterDeps,
} from "./ingest-adapter.js";
export {
  normalizeAcquisition,
  normalizeAcquisitions,
  runAcquisitionPull,
  ACQUISITION_EVENT,
} from "./msstore-puller.js";
export type {
  MsStoreAcquisitionRow,
  AcquisitionSource,
  PullerDeps,
  PullResult,
} from "./msstore-puller.js";
export { createSharedRateLimiter, createSharedReplayCache } from "./ingest-store.js";
export type { SharedStore, SharedRateLimitOptions } from "./ingest-store.js";
export { createEmitter, makeHmacSigner } from "./emitter.js";
export type {
  Emitter,
  EmitterConfig,
  EmitterTransport,
  ClientIdStore,
  FlushResult,
} from "./emitter.js";
export {
  createFetchTransport,
  createPersistentClientIdStore,
  createMemoryClientIdStore,
  defaultGenId,
} from "./emitter-adapter.js";
export type { FetchLike, KeyValueStorage } from "./emitter-adapter.js";

/** Default starter allowlist — extend per app. Unknown names are dropped server-side. */
export const DEFAULT_ALLOWLIST: ReadonlySet<string> = new Set([
  "app_open",
  "purchase",
]);
