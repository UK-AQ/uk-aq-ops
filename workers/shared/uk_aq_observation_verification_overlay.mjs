// @ts-nocheck -- shared deterministic verification-overlay model for Workers and Node tools.

export const OBSERVATION_VERIFICATION_FORMAT_VERSION = 1;
export const OBSERVATION_VERIFICATION_CONNECTOR_MANIFEST_KIND =
  "uk_aq_observation_verification_connector_manifest";
export const OBSERVATION_VERIFICATION_LATEST_KIND =
  "uk_aq_observation_verification_latest";
export const OBSERVATION_VERIFICATION_ROOT = "history/v3/verification";
export const OBSERVATION_VERIFICATION_LATEST_KEY =
  "history/_index_v3/verification/latest.json";
export const OBSERVATION_VERIFICATION_RATIFICATION_BOUNDARY_MODEL =
  "ratification-boundary-v1";
export const OBSERVATION_VERIFICATION_PER_OBSERVATION_MODEL =
  "per-observation-status-v1";
export const OBSERVATION_VERIFICATION_LATEST_CACHE_MAX_AGE_SECONDS = 60;
export const OBSERVATION_VERIFICATION_MANIFEST_CACHE_MAX_AGE_SECONDS = 31_536_000;

const SHA256 = /^[0-9a-f]{64}$/;
const POLLUTANT = /^[a-z0-9_]+$/;
const UTC_DAY = /^\d{4}-\d{2}-\d{2}$/;
const VOLATILE_ACQUISITION_FIELDS = new Set([
  "retrieved_at_utc",
  "downloaded_at_utc",
  "download_timestamp",
  "source_file_sha256",
  "downloaded_file_sha256",
  "source_sha256",
  "source_byte_size",
  "response_byte_size",
  "http_etag",
  "transient_etag",
  "etag",
  "http_response_identity",
  "decoder_execution_metadata",
  "decoder_run_id",
]);
const VERIFICATION_CACHE_ORIGIN = "https://uk-aq.internal";
const encoder = new TextEncoder();

function bytewiseCompare(left, right) {
  const leftBytes = encoder.encode(String(left));
  const rightBytes = encoder.encode(String(right));
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) {
      return leftBytes[index] - rightBytes[index];
    }
  }
  return leftBytes.length - rightBytes.length;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort(bytewiseCompare)
      .map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export function encodeObservationVerificationJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

function positiveInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return number;
}

function nullablePositiveInteger(value, label) {
  if (value === null || value === undefined) return null;
  return positiveInteger(value, label);
}

function canonicalStatus(value, label, { nullable = false } = {}) {
  if (nullable && (value === null || value === undefined)) return null;
  if (value !== "P" && value !== "R") {
    throw new TypeError(`${label} must be P${nullable ? ", R or null" : " or R"}`);
  }
  return value;
}

function canonicalUtc(value, label, { nullable = false } = {}) {
  if (nullable && (value === null || value === undefined)) return null;
  const text = String(value || "").trim();
  const parsed = new Date(text);
  if (!text || Number.isNaN(parsed.getTime()) || parsed.toISOString() !== text) {
    throw new TypeError(`${label} must be a canonical UTC ISO timestamp`);
  }
  return text;
}

function canonicalPollutant(value, label) {
  const text = String(value || "").trim();
  if (!POLLUTANT.test(text) || text !== text.toLowerCase()) {
    throw new TypeError(`${label} must be a canonical lower-case pollutant code`);
  }
  return text;
}

function canonicalKey(value, label) {
  const key = String(value || "").trim().replace(/^\/+/, "");
  if (!key || key.endsWith("/") || key.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new TypeError(`${label} is invalid`);
  }
  return key;
}

function canonicalSha256(value, label) {
  const sha256 = String(value || "").trim();
  if (!SHA256.test(sha256)) throw new TypeError(`${label} must be lower-case SHA-256`);
  return sha256;
}

function canonicalObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return canonicalize(value);
}

function rejectVolatileAcquisitionEvidence(value, label, path = label) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      rejectVolatileAcquisitionEvidence(entry, label, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if (VOLATILE_ACQUISITION_FIELDS.has(key)) {
      throw new TypeError(
        `${path}.${key} is acquisition audit evidence and must not enter canonical semantic manifest identity`,
      );
    }
    rejectVolatileAcquisitionEvidence(entry, label, `${path}.${key}`);
  }
}

function canonicalSemanticProvenance(value, label) {
  const canonical = canonicalObject(value, label);
  rejectVolatileAcquisitionEvidence(canonical, label);
  return canonical;
}

export function normalizeObservationVerificationPeriods(periods = []) {
  if (!Array.isArray(periods)) {
    throw new TypeError("verification periods must be an array");
  }
  const collapsed = [];
  let previousFrom = null;
  for (const [index, raw] of periods.entries()) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new TypeError(`verification periods[${index}] must be an object`);
    }
    const period = {
      from_observed_at_utc: canonicalUtc(
        raw.from_observed_at_utc,
        `verification periods[${index}].from_observed_at_utc`,
        { nullable: true },
      ),
      to_observed_at_utc: canonicalUtc(
        raw.to_observed_at_utc,
        `verification periods[${index}].to_observed_at_utc`,
        { nullable: true },
      ),
      status: canonicalStatus(raw.status, `verification periods[${index}].status`),
    };
    if (
      period.from_observed_at_utc !== null &&
      period.to_observed_at_utc !== null &&
      period.from_observed_at_utc >= period.to_observed_at_utc
    ) {
      throw new Error(`verification periods[${index}] is empty or reversed`);
    }
    if (index > 0 && period.from_observed_at_utc === null) {
      throw new Error("only the first verification period may have an open start");
    }
    if (index < periods.length - 1 && period.to_observed_at_utc === null) {
      throw new Error("only the last verification period may have an open end");
    }
    if (
      previousFrom !== null &&
      period.from_observed_at_utc !== null &&
      period.from_observed_at_utc < previousFrom
    ) {
      throw new Error("verification periods must be sorted deterministically");
    }
    const previous = collapsed.at(-1);
    if (previous) {
      if (previous.to_observed_at_utc === null) {
        throw new Error("an open-ended verification period must be last");
      }
      if (
        period.from_observed_at_utc === null ||
        period.from_observed_at_utc < previous.to_observed_at_utc
      ) {
        throw new Error("verification periods must not overlap");
      }
      if (
        period.from_observed_at_utc === previous.to_observed_at_utc &&
        period.status === previous.status
      ) {
        previous.to_observed_at_utc = period.to_observed_at_utc;
        previousFrom = period.from_observed_at_utc;
        continue;
      }
    }
    collapsed.push(period);
    previousFrom = period.from_observed_at_utc;
  }
  return collapsed.map((period) => Object.freeze({ ...period }));
}

export function verificationPeriodsFromRatifiedTo(
  ratifiedTo,
  { semanticSourceProvenance = {} } = {},
) {
  const stableProvenance = canonicalSemanticProvenance(
    semanticSourceProvenance,
    "semanticSourceProvenance",
  );
  const sourceValue = ratifiedTo === null || ratifiedTo === undefined
    ? null
    : String(ratifiedTo).trim();
  if (sourceValue === null || sourceValue === "" || sourceValue.toLowerCase() === "never") {
    return Object.freeze({
      source_verification_model: OBSERVATION_VERIFICATION_RATIFICATION_BOUNDARY_MODEL,
      semantic_source_provenance: Object.freeze({
        ...stableProvenance,
        ratified_to: sourceValue || null,
      }),
      default_status: "P",
      periods: Object.freeze([]),
    });
  }
  const parsed = new Date(`${sourceValue}T00:00:00.000Z`);
  if (
    !UTC_DAY.test(sourceValue) || Number.isNaN(parsed.getTime()) ||
    parsed.toISOString().slice(0, 10) !== sourceValue
  ) {
    throw new TypeError("ratified_to must be YYYY-MM-DD, Never or a valid missing value");
  }
  const nextMidnight = new Date(parsed.getTime() + 86_400_000).toISOString();
  return Object.freeze({
    source_verification_model: OBSERVATION_VERIFICATION_RATIFICATION_BOUNDARY_MODEL,
    semantic_source_provenance: Object.freeze({
      ...stableProvenance,
      ratified_to: sourceValue,
    }),
    default_status: "P",
    periods: Object.freeze(normalizeObservationVerificationPeriods([{
      from_observed_at_utc: null,
      to_observed_at_utc: nextMidnight,
      status: "R",
    }])),
  });
}

export function verificationPeriodsFromObservationEvidence(
  evidence = [],
  { semanticSourceProvenance = {} } = {},
) {
  if (!Array.isArray(evidence)) {
    throw new TypeError("source observation verification evidence must be an array");
  }
  const transitions = [];
  let previousTimestamp = null;
  for (const [index, raw] of evidence.entries()) {
    const observedAtUtc = canonicalUtc(
      raw?.observed_at_utc,
      `source evidence[${index}].observed_at_utc`,
    );
    const status = canonicalStatus(raw?.status, `source evidence[${index}].status`);
    if (previousTimestamp !== null && observedAtUtc < previousTimestamp) {
      throw new Error("source observation verification evidence must be ordered");
    }
    const previous = transitions.at(-1);
    if (previousTimestamp === observedAtUtc) {
      if (previous.status !== status) {
        throw new Error("source observation verification evidence contradicts at one timestamp");
      }
      continue;
    }
    if (!previous || previous.status !== status) {
      transitions.push({ observed_at_utc: observedAtUtc, status });
    }
    previousTimestamp = observedAtUtc;
  }
  const periods = transitions.map((transition, index) => ({
    from_observed_at_utc: transition.observed_at_utc,
    to_observed_at_utc: transitions[index + 1]?.observed_at_utc ?? null,
    status: transition.status,
  }));
  return Object.freeze({
    source_verification_model: OBSERVATION_VERIFICATION_PER_OBSERVATION_MODEL,
    semantic_source_provenance: Object.freeze(canonicalSemanticProvenance(
      semanticSourceProvenance,
      "semanticSourceProvenance",
    )),
    default_status: "P",
    periods: Object.freeze(normalizeObservationVerificationPeriods(periods)),
  });
}

function normalizeTimeseriesEntry(raw, connectorId, { canonical = false } = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TypeError("verification timeseries entry must be an object");
  }
  const entryConnectorId = positiveInteger(raw.connector_id, "timeseries.connector_id");
  if (entryConnectorId !== connectorId) {
    throw new Error("verification timeseries connector_id does not match manifest");
  }
  const sourceModel = String(raw.source_verification_model || "").trim();
  if (![OBSERVATION_VERIFICATION_RATIFICATION_BOUNDARY_MODEL,
    OBSERVATION_VERIFICATION_PER_OBSERVATION_MODEL].includes(sourceModel)) {
    throw new TypeError("timeseries.source_verification_model is unsupported");
  }
  const semanticProvenance = canonical
    ? raw.source_provenance
    : raw.semantic_source_provenance;
  if (!canonical && Object.hasOwn(raw, "source_provenance")) {
    throw new TypeError(
      "timeseries builder input must use semantic_source_provenance; acquisition evidence is separate",
    );
  }
  return {
    connector_id: entryConnectorId,
    timeseries_id: positiveInteger(raw.timeseries_id, "timeseries.timeseries_id"),
    station_id: nullablePositiveInteger(raw.station_id, "timeseries.station_id"),
    pollutant_code: canonicalPollutant(raw.pollutant_code, "timeseries.pollutant_code"),
    source_verification_model: sourceModel,
    source_provenance: canonicalSemanticProvenance(
      semanticProvenance,
      canonical
        ? "timeseries.source_provenance"
        : "timeseries.semantic_source_provenance",
    ),
    default_status: canonicalStatus(
      raw.default_status,
      "timeseries.default_status",
      { nullable: true },
    ),
    periods: normalizeObservationVerificationPeriods(raw.periods || []),
  };
}

export function buildObservationVerificationConnectorManifest({
  connectorId,
  semanticSourceIdentity,
  timeseries,
}) {
  const connector = positiveInteger(connectorId, "connectorId");
  const normalizedTimeseries = (Array.isArray(timeseries) ? timeseries : [])
    .map((entry) => normalizeTimeseriesEntry(entry, connector))
    .sort((left, right) => left.timeseries_id - right.timeseries_id);
  for (let index = 1; index < normalizedTimeseries.length; index += 1) {
    if (normalizedTimeseries[index - 1].timeseries_id === normalizedTimeseries[index].timeseries_id) {
      throw new Error("verification connector manifest contains duplicate timeseries_id");
    }
  }
  return Object.freeze({
    schema_version: OBSERVATION_VERIFICATION_FORMAT_VERSION,
    kind: OBSERVATION_VERIFICATION_CONNECTOR_MANIFEST_KIND,
    verification_format_version: OBSERVATION_VERIFICATION_FORMAT_VERSION,
    history_generation: "v3",
    connector_id: connector,
    source_identity: canonicalSemanticProvenance(
      semanticSourceIdentity,
      "semanticSourceIdentity",
    ),
    timeseries: Object.freeze(normalizedTimeseries.map((entry) => Object.freeze(entry))),
  });
}

export function buildObservationVerificationRefreshInputs({
  connectorId,
  semanticSourceIdentity,
  timeseries,
  acquisitionEvidence,
}) {
  return Object.freeze({
    canonical_manifest: buildObservationVerificationConnectorManifest({
      connectorId,
      semanticSourceIdentity,
      timeseries,
    }),
    acquisition_audit_evidence: Object.freeze(canonicalObject(
      acquisitionEvidence,
      "acquisitionEvidence",
    )),
  });
}

export function validateObservationVerificationConnectorManifest(raw) {
  if (
    raw?.schema_version !== OBSERVATION_VERIFICATION_FORMAT_VERSION ||
    raw?.kind !== OBSERVATION_VERIFICATION_CONNECTOR_MANIFEST_KIND ||
    raw?.verification_format_version !== OBSERVATION_VERIFICATION_FORMAT_VERSION ||
    raw?.history_generation !== "v3"
  ) throw new Error("verification connector manifest identity is invalid");
  const connector = positiveInteger(raw.connector_id, "connector_id");
  const normalizedTimeseries = (Array.isArray(raw.timeseries) ? raw.timeseries : [])
    .map((entry) => normalizeTimeseriesEntry(entry, connector, { canonical: true }))
    .sort((left, right) => left.timeseries_id - right.timeseries_id);
  for (let index = 1; index < normalizedTimeseries.length; index += 1) {
    if (normalizedTimeseries[index - 1].timeseries_id === normalizedTimeseries[index].timeseries_id) {
      throw new Error("verification connector manifest contains duplicate timeseries_id");
    }
  }
  const normalized = Object.freeze({
    schema_version: OBSERVATION_VERIFICATION_FORMAT_VERSION,
    kind: OBSERVATION_VERIFICATION_CONNECTOR_MANIFEST_KIND,
    verification_format_version: OBSERVATION_VERIFICATION_FORMAT_VERSION,
    history_generation: "v3",
    connector_id: connector,
    source_identity: canonicalSemanticProvenance(
      raw.source_identity,
      "source_identity",
    ),
    timeseries: Object.freeze(normalizedTimeseries.map((entry) => Object.freeze(entry))),
  });
  if (encodeObservationVerificationJson(raw) !== encodeObservationVerificationJson(normalized)) {
    throw new Error("verification connector manifest is not canonical");
  }
  return normalized;
}

export function observationVerificationConnectorManifestKey(
  connectorId,
  manifestSha256,
) {
  return `${OBSERVATION_VERIFICATION_ROOT}/connector_id=${positiveInteger(
    connectorId,
    "connectorId",
  )}/manifests/${canonicalSha256(
    manifestSha256,
    "manifestSha256",
  )}.json`;
}

function normalizeManifestIdentity(raw) {
  const connectorId = positiveInteger(raw?.connector_id, "connector identity.connector_id");
  const identity = {
    connector_id: connectorId,
    key: canonicalKey(raw?.key, "connector identity.key"),
    byte_size: positiveInteger(raw?.byte_size, "connector identity.byte_size"),
    sha256: canonicalSha256(raw?.sha256, "connector identity.sha256"),
  };
  if (
    identity.key !== observationVerificationConnectorManifestKey(
      connectorId,
      identity.sha256,
    )
  ) {
    throw new Error(
      "verification connector identity key is not canonical for its connector and SHA-256",
    );
  }
  return identity;
}

export function buildObservationVerificationLatest({ connectorManifests = [] } = {}) {
  const connectors = connectorManifests
    .map(normalizeManifestIdentity)
    .sort((left, right) => left.connector_id - right.connector_id);
  for (let index = 1; index < connectors.length; index += 1) {
    if (connectors[index - 1].connector_id === connectors[index].connector_id) {
      throw new Error("verification latest contains duplicate connector_id");
    }
  }
  return Object.freeze({
    schema_version: OBSERVATION_VERIFICATION_FORMAT_VERSION,
    kind: OBSERVATION_VERIFICATION_LATEST_KIND,
    verification_format_version: OBSERVATION_VERIFICATION_FORMAT_VERSION,
    history_generation: "v3",
    connectors: Object.freeze(connectors.map((entry) => Object.freeze(entry))),
  });
}

export function validateObservationVerificationLatest(raw) {
  if (
    raw?.schema_version !== OBSERVATION_VERIFICATION_FORMAT_VERSION ||
    raw?.kind !== OBSERVATION_VERIFICATION_LATEST_KIND ||
    raw?.verification_format_version !== OBSERVATION_VERIFICATION_FORMAT_VERSION ||
    raw?.history_generation !== "v3"
  ) throw new Error("verification latest identity is invalid");
  const normalized = buildObservationVerificationLatest({
    connectorManifests: raw.connectors,
  });
  if (encodeObservationVerificationJson(raw) !== encodeObservationVerificationJson(normalized)) {
    throw new Error("verification latest is not canonical");
  }
  return normalized;
}

export async function sha256ObservationVerificationBytes(value) {
  const bytes = typeof value === "string" ? encoder.encode(value) :
    value instanceof Uint8Array ? value : new Uint8Array(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")).join("");
}

export async function buildObservationVerificationArtifact({ key, payload }) {
  const body = encoder.encode(encodeObservationVerificationJson(payload));
  return Object.freeze({
    key: canonicalKey(key, "verification artifact key"),
    body,
    byte_size: body.byteLength,
    sha256: await sha256ObservationVerificationBytes(body),
    content_type: "application/json; charset=utf-8",
  });
}

export async function buildObservationVerificationConnectorArtifact(payload) {
  const canonicalManifest = validateObservationVerificationConnectorManifest(payload);
  const body = encoder.encode(encodeObservationVerificationJson(canonicalManifest));
  const sha256 = await sha256ObservationVerificationBytes(body);
  return Object.freeze({
    key: observationVerificationConnectorManifestKey(
      canonicalManifest.connector_id,
      sha256,
    ),
    body,
    byte_size: body.byteLength,
    sha256,
    content_type: "application/json; charset=utf-8",
  });
}

async function r2ObjectBytes(object) {
  if (typeof object?.arrayBuffer === "function") {
    return new Uint8Array(await object.arrayBuffer());
  }
  if (object?.body instanceof Uint8Array) return object.body;
  if (object?.body instanceof ArrayBuffer) return new Uint8Array(object.body);
  throw new Error("verification R2 object body is not readable");
}

function parseVerificationJson(bytes, label) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8 JSON`, { cause: error });
  }
}

function cacheTimestamp(response) {
  const value = Number(response?.headers?.get("x-uk-aq-cached-at-ms"));
  return Number.isFinite(value) && value >= 0 ? value : null;
}

function latestCacheRequest() {
  return new Request(
    `${VERIFICATION_CACHE_ORIGIN}/_cache/observation-verification/latest-v1`,
  );
}

function manifestCacheRequest(identity) {
  const url = new URL(
    `${VERIFICATION_CACHE_ORIGIN}/_cache/observation-verification/manifest-v1`,
  );
  url.searchParams.set("connector_id", String(identity.connector_id));
  url.searchParams.set("key", identity.key);
  url.searchParams.set("byte_size", String(identity.byte_size));
  url.searchParams.set("sha256", identity.sha256);
  return new Request(url.toString());
}

async function cachePut(cache, request, bytes, {
  nowMs,
  maxAgeSeconds,
  absent = false,
}) {
  if (!cache || typeof cache.put !== "function") return;
  const response = new Response(absent ? new Uint8Array() : bytes, {
    headers: {
      "Cache-Control": `public, max-age=${maxAgeSeconds}`,
      "Content-Type": "application/octet-stream",
      "x-uk-aq-cached-at-ms": String(nowMs),
      "x-uk-aq-cache-absent": absent ? "1" : "0",
    },
  });
  await cache.put(request, response);
}

function buildVerificationDiscovery(latestBytes, { cacheStatus }) {
  if (latestBytes === null) {
    return Object.freeze({
      latest_present: false,
      latest: null,
      latest_identity: null,
      cache_status: cacheStatus,
    });
  }
  const latest = validateObservationVerificationLatest(
    parseVerificationJson(latestBytes, "verification latest"),
  );
  return sha256ObservationVerificationBytes(latestBytes).then((sha256) =>
    Object.freeze({
      latest_present: true,
      latest,
      latest_identity: Object.freeze({
        key: OBSERVATION_VERIFICATION_LATEST_KEY,
        byte_size: latestBytes.byteLength,
        sha256,
      }),
      cache_status: cacheStatus,
    }));
}

export async function loadObservationVerificationDiscovery({
  bucket,
  cache = null,
  nowMs = Date.now(),
}) {
  if (!bucket || typeof bucket.get !== "function") {
    throw new TypeError("verification discovery requires an R2 bucket");
  }
  const currentTime = Number(nowMs);
  if (!Number.isFinite(currentTime) || currentTime < 0) {
    throw new TypeError("nowMs must be a non-negative finite number");
  }
  const request = latestCacheRequest();
  if (cache && typeof cache.match === "function") {
    const cached = await cache.match(request);
    const cachedAt = cacheTimestamp(cached);
    if (
      cached && cachedAt !== null && currentTime >= cachedAt &&
      currentTime - cachedAt <=
        OBSERVATION_VERIFICATION_LATEST_CACHE_MAX_AGE_SECONDS * 1000
    ) {
      if (cached.headers.get("x-uk-aq-cache-absent") === "1") {
        return buildVerificationDiscovery(null, { cacheStatus: "hit_absent" });
      }
      const bytes = new Uint8Array(await cached.arrayBuffer());
      return buildVerificationDiscovery(bytes, { cacheStatus: "hit" });
    }
  }

  const latestObject = await bucket.get(OBSERVATION_VERIFICATION_LATEST_KEY);
  if (!latestObject) {
    await cachePut(cache, request, new Uint8Array(), {
      nowMs: currentTime,
      maxAgeSeconds: OBSERVATION_VERIFICATION_LATEST_CACHE_MAX_AGE_SECONDS,
      absent: true,
    });
    return buildVerificationDiscovery(null, { cacheStatus: "miss_absent" });
  }
  const latestBytes = await r2ObjectBytes(latestObject);
  const discovery = await buildVerificationDiscovery(latestBytes, {
    cacheStatus: "miss",
  });
  await cachePut(cache, request, latestBytes, {
    nowMs: currentTime,
    maxAgeSeconds: OBSERVATION_VERIFICATION_LATEST_CACHE_MAX_AGE_SECONDS,
  });
  return discovery;
}

export function observationVerificationManifestIdentityForConnector({
  discovery,
  connectorId,
}) {
  const connector = positiveInteger(connectorId, "connectorId");
  if (!discovery?.latest_present) return null;
  return discovery.latest.connectors.find((entry) =>
    entry.connector_id === connector) || null;
}

async function readCachedManifest(cache, identity) {
  if (!cache || typeof cache.match !== "function") return null;
  const cached = await cache.match(manifestCacheRequest(identity));
  if (!cached) return null;
  const bytes = new Uint8Array(await cached.arrayBuffer());
  if (
    bytes.byteLength !== identity.byte_size ||
    await sha256ObservationVerificationBytes(bytes) !== identity.sha256
  ) return null;
  const manifest = validateObservationVerificationConnectorManifest(
    parseVerificationJson(bytes, "cached verification connector manifest"),
  );
  if (manifest.connector_id !== identity.connector_id) return null;
  return Object.freeze({ bytes, manifest });
}

export async function loadObservationVerificationAuthority({
  bucket,
  connectorId,
  discovery = null,
  cache = null,
  nowMs = Date.now(),
}) {
  const connector = positiveInteger(connectorId, "connectorId");
  const resolvedDiscovery = discovery ||
    await loadObservationVerificationDiscovery({ bucket, cache, nowMs });
  if (!resolvedDiscovery.latest_present) {
    return Object.freeze({
      latest_present: false,
      overlay_authoritative: false,
      connector_id: connector,
      manifest: null,
      manifest_identity: null,
      cache_identity: "legacy-embedded-status",
      discovery_cache_status: resolvedDiscovery.cache_status,
      manifest_cache_status: "not_applicable",
    });
  }
  const manifestIdentity = observationVerificationManifestIdentityForConnector({
    discovery: resolvedDiscovery,
    connectorId: connector,
  });
  if (!manifestIdentity) {
    return Object.freeze({
      latest_present: true,
      overlay_authoritative: false,
      connector_id: connector,
      latest_identity: resolvedDiscovery.latest_identity,
      manifest: null,
      manifest_identity: null,
      cache_identity: "legacy-embedded-status",
      discovery_cache_status: resolvedDiscovery.cache_status,
      manifest_cache_status: "not_applicable",
    });
  }

  const cachedManifest = await readCachedManifest(cache, manifestIdentity);
  if (cachedManifest) {
    return Object.freeze({
      latest_present: true,
      overlay_authoritative: true,
      connector_id: connector,
      latest_identity: resolvedDiscovery.latest_identity,
      manifest: cachedManifest.manifest,
      manifest_identity: manifestIdentity,
      cache_identity: manifestIdentity.sha256,
      discovery_cache_status: resolvedDiscovery.cache_status,
      manifest_cache_status: "hit",
    });
  }
  const manifestObject = await bucket.get(manifestIdentity.key);
  if (!manifestObject) {
    throw new Error(`verification latest references a missing connector manifest: ${manifestIdentity.key}`);
  }
  const manifestBytes = await r2ObjectBytes(manifestObject);
  if (
    manifestBytes.byteLength !== manifestIdentity.byte_size ||
    await sha256ObservationVerificationBytes(manifestBytes) !== manifestIdentity.sha256
  ) {
    throw new Error(`verification connector manifest identity mismatch: ${manifestIdentity.key}`);
  }
  const manifest = validateObservationVerificationConnectorManifest(
    parseVerificationJson(manifestBytes, "verification connector manifest"),
  );
  if (manifest.connector_id !== connector) {
    throw new Error("verification connector manifest connector_id mismatch");
  }
  await cachePut(cache, manifestCacheRequest(manifestIdentity), manifestBytes, {
    nowMs: Number(nowMs),
    maxAgeSeconds: OBSERVATION_VERIFICATION_MANIFEST_CACHE_MAX_AGE_SECONDS,
  });
  return Object.freeze({
    latest_present: true,
    overlay_authoritative: true,
    connector_id: connector,
    latest_identity: resolvedDiscovery.latest_identity,
    manifest,
    manifest_identity: manifestIdentity,
    cache_identity: manifestIdentity.sha256,
    discovery_cache_status: resolvedDiscovery.cache_status,
    manifest_cache_status: "miss",
  });
}

export function resolveEffectiveObservationVerificationStatus({
  authority,
  timeseriesId,
  observedAtUtc,
  legacyStatus = null,
}) {
  if (!authority?.overlay_authoritative) {
    return legacyStatus === "P" || legacyStatus === "R" ? legacyStatus : null;
  }
  const timeseries = positiveInteger(timeseriesId, "timeseriesId");
  const observedAt = canonicalUtc(observedAtUtc, "observedAtUtc");
  const entry = authority.manifest.timeseries.find((candidate) =>
    candidate.timeseries_id === timeseries);
  if (!entry) return null;
  for (const period of entry.periods) {
    const afterStart = period.from_observed_at_utc === null ||
      observedAt >= period.from_observed_at_utc;
    const beforeEnd = period.to_observed_at_utc === null ||
      observedAt < period.to_observed_at_utc;
    if (afterStart && beforeEnd) return period.status;
  }
  return entry.default_status;
}

export function applyObservationVerificationOverlay({
  rows,
  authority,
  timeseriesId,
  timestampField = "observed_at_utc",
}) {
  return (Array.isArray(rows) ? rows : []).map((row) => ({
    ...row,
    verification_status: resolveEffectiveObservationVerificationStatus({
      authority,
      timeseriesId,
      observedAtUtc: row?.[timestampField],
      legacyStatus: row?.verification_status,
    }),
  }));
}
