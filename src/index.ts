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
export { handleIngest, MAX_BODY_BYTES, REPLAY_WINDOW_MS, KeyStoreUnavailableError } from "./ingest.js";
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
  createPerInstallKeyResolver,
  CLIENT_ID_KEY_PATTERN,
  createInMemoryReplayCache,
  createInMemoryRateLimiter,
  createInMemoryIpRateGate,
  createCoarseGeo,
  makeBqInsert,
  rowInsertId,
  createAppCheckVerifier,
  createIngestHttpHandler,
} from "./ingest-adapter.js";
export type {
  SecretLookup,
  PerInstallKeyStore,
  PerInstallKeyOptions,
  RateLimitOptions,
  GeoOptions,
  BqWriter,
  RawHttpRequest,
  HttpResult,
  AdapterDeps,
} from "./ingest-adapter.js";
export { deriveClientKey, createDerivedKeyStore, createInMemoryRevocationList } from "./derived-key.js";
export type { RevocationList, DerivedKeyStoreOptions } from "./derived-key.js";
export { countLeadingZeroBits, powHash, verifyPowSolution, solvePow } from "./pow.js";
export { issueChallenge, verifyPowChallenge, challengeId } from "./provision-pow.js";
export type { PowChallenge, PowSolution, PowVerifyResult, ChallengeIssueOptions, PowVerifyOptions } from "./provision-pow.js";
export { handleProvision, MAX_PROVISION_BODY_BYTES } from "./provision.js";
export type {
  ProvisionDeps,
  ProvisionRequest,
  ProvisionResponse,
  ProvisionGate,
  KeyProvisioner,
  ProvisionPersistResult,
} from "./provision.js";
export { createCryptoProvisionGen, createProvisionHttpHandler, PROVISION_CLIENT_ID_PATTERN } from "./provision-adapter.js";
export type { ProvisionAdapterDeps } from "./provision-adapter.js";
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
export {
  createAzureAdTokenIssuer,
  createMsStoreAcquisitionSource,
  isValidAzureTenant,
  isValidAzureClientId,
} from "./msstore-live.js";
export type { FetchJson, AzureAdConfig, MsStoreSourceConfig } from "./msstore-live.js";
export { createSteamEntitlementVerifier } from "./steam-entitlement.js";
export type { SteamEntitlementConfig } from "./steam-entitlement.js";
export { createSharedRateLimiter, createSharedReplayCache, createSharedProvisionGate } from "./ingest-store.js";
export type { SharedStore, SharedRateLimitOptions, SharedProvisionGateOptions } from "./ingest-store.js";
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
