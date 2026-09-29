import path from "node:path";

import {
  joinTargetPath,
  rcloneCat,
  rcloneDeleteFile,
  rcloneLsjsonRecursive,
} from "./rclone.mjs";

function normalizePosixRelativePath(rawPath) {
  const cleaned = String(rawPath || "")
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\/+/, "");
  if (!cleaned || cleaned.includes("\0")) return "";
  const normalized = path.posix.normalize(cleaned);
  if (
    !normalized
    || normalized === "."
    || normalized === ".."
    || normalized.startsWith("../")
  ) {
    return "";
  }
  return normalized;
}

function pathFromLsjsonEntry(entry) {
  return normalizePosixRelativePath(entry?.Path || entry?.Name || "");
}

function toUnitRelativeManifestPath(
  rawPath,
  unitRelativePath,
  manifestRelativePath,
) {
  const raw = normalizePosixRelativePath(rawPath);
  if (!raw || !raw.endsWith(".parquet")) return null;

  const unit = normalizePosixRelativePath(unitRelativePath);
  if (!unit) {
    throw new Error(`Invalid prune unit path: ${unitRelativePath}`);
  }

  let relPath = "";
  if (raw === unit || raw.startsWith(`${unit}/`)) {
    relPath = raw.slice(unit.length).replace(/^\/+/, "");
  } else if (raw.startsWith("history/")) {
    throw new Error(
      `Manifest parquet path is outside prune unit: unit=${unit} path=${raw}`,
    );
  } else if (raw.includes("/")) {
    relPath = raw;
  } else {
    const manifestRel = normalizePosixRelativePath(manifestRelativePath);
    const manifestDir = manifestRel && manifestRel.includes("/")
      ? path.posix.dirname(manifestRel)
      : "";
    relPath = manifestDir ? path.posix.join(manifestDir, raw) : raw;
  }

  const normalizedRel = normalizePosixRelativePath(relPath);
  if (
    !normalizedRel
    || normalizedRel.startsWith("history/")
    || !normalizedRel.endsWith(".parquet")
  ) {
    throw new Error(
      `Manifest parquet path cannot be normalized safely: unit=${unit} path=${raw}`,
    );
  }
  return normalizedRel;
}

function addManifestParquetReference(references, rawPath, context) {
  const relPath = toUnitRelativeManifestPath(
    rawPath,
    context.unit_relative_path,
    context.manifest_relative_path,
  );
  if (!relPath) return;
  const manifests = references.get(relPath) || new Set();
  manifests.add(context.manifest_relative_path);
  references.set(relPath, manifests);
}

function collectManifestParquetReferences(manifests, unitRelativePath) {
  const references = new Map();
  for (const entry of manifests) {
    const manifestRelativePath = normalizePosixRelativePath(
      entry?.relative_path || "",
    );
    if (!manifestRelativePath || !manifestRelativePath.endsWith("manifest.json")) {
      throw new Error(
        `Invalid manifest path for prune unit ${unitRelativePath}: `
        + `${entry?.relative_path || ""}`,
      );
    }
    let manifest;
    try {
      manifest = JSON.parse(String(entry?.text || ""));
    } catch (error) {
      throw new Error(
        `Failed to parse manifest for prune unit ${unitRelativePath} at `
        + `${manifestRelativePath}: ${error?.message || error}`,
      );
    }
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
      throw new Error(
        `Manifest root is not a JSON object for prune unit `
        + `${unitRelativePath} at ${manifestRelativePath}`,
      );
    }

    const context = {
      unit_relative_path: unitRelativePath,
      manifest_relative_path: manifestRelativePath,
    };
    if (Array.isArray(manifest.parquet_object_keys)) {
      for (const rawPath of manifest.parquet_object_keys) {
        addManifestParquetReference(references, rawPath, context);
      }
    }
    if (Array.isArray(manifest.files)) {
      for (const fileEntry of manifest.files) {
        addManifestParquetReference(
          references,
          fileEntry?.key
            || fileEntry?.relative_path
            || fileEntry?.path
            || fileEntry?.name,
          context,
        );
      }
    }
  }
  return references;
}

function divergenceScope(relativePath) {
  const match = String(relativePath).match(
    /(?:^|\/)connector_id=([1-9]\d*)(?:\/pollutant_code=([^/]+))?/,
  );
  return {
    connector_id: match ? Number(match[1]) : null,
    pollutant_code: match?.[2] || null,
  };
}

export function buildStaleParquetPrunePlan({
  unit_relative_path,
  manifest_entries,
  destination_manifest_entries,
  actual_file_entries,
} = {}) {
  const unitRelativePath = normalizePosixRelativePath(unit_relative_path);
  if (!unitRelativePath) {
    throw new Error(`Invalid prune unit path: ${unit_relative_path}`);
  }
  const manifests = Array.isArray(manifest_entries) ? manifest_entries : [];
  if (manifests.length === 0) {
    throw new Error(`No manifest.json files found for prune unit: ${unitRelativePath}`);
  }
  const destinationManifests = Array.isArray(destination_manifest_entries)
    ? destination_manifest_entries
    : [];
  const authoritativeReferences = collectManifestParquetReferences(
    manifests,
    unitRelativePath,
  );
  const destinationReferences = collectManifestParquetReferences(
    destinationManifests,
    unitRelativePath,
  );

  const actualPaths = new Set();
  for (const entry of Array.isArray(actual_file_entries) ? actual_file_entries : []) {
    const relPath = pathFromLsjsonEntry(entry);
    if (relPath && relPath.endsWith(".parquet")) {
      actualPaths.add(relPath);
    }
  }

  if (authoritativeReferences.size === 0 && actualPaths.size > 0) {
    throw new Error(
      `No manifest-referenced Parquet paths found for prune unit `
      + `${unitRelativePath}; refusing to delete destination files`,
    );
  }

  const allStalePaths = Array.from(actualPaths)
    .filter((relPath) => !authoritativeReferences.has(relPath))
    .sort();
  const manifestBackedDivergences = allStalePaths
    .filter((relPath) => destinationReferences.has(relPath))
    .map((relPath) => {
      const manifestRelativePaths = [...destinationReferences.get(relPath)].sort();
      const scope = divergenceScope(manifestRelativePaths[0] || relPath);
      return {
        ...scope,
        parquet_relative_path: relPath,
        parquet_key: `${unitRelativePath}/${relPath}`,
        manifest_relative_paths: manifestRelativePaths,
        manifest_keys: manifestRelativePaths.map((manifestPath) =>
          `${unitRelativePath}/${manifestPath}`),
      };
    });
  const protectedPaths = new Set(manifestBackedDivergences.map((entry) =>
    entry.parquet_relative_path));

  return {
    unit_relative_path: unitRelativePath,
    manifest_count: manifests.length,
    destination_manifest_count: destinationManifests.length,
    manifest_referenced_parquet_count: authoritativeReferences.size,
    destination_manifest_referenced_parquet_count: destinationReferences.size,
    actual_destination_parquet_count: actualPaths.size,
    stale_relative_paths: allStalePaths.filter((relPath) => !protectedPaths.has(relPath)),
    manifest_backed_divergence_count: manifestBackedDivergences.length,
    manifest_backed_divergences: manifestBackedDivergences,
  };
}

export class ManifestBackedParquetDivergenceError extends Error {
  constructor(plan) {
    const sample = plan.manifest_backed_divergences[0];
    super(
      `Manifest-backed destination Parquet divergence for ${plan.unit_relative_path}; `
      + `count=${plan.manifest_backed_divergence_count}; `
      + `manifest=${sample?.manifest_keys?.[0] || "unknown"}; `
      + `parquet=${sample?.parquet_key || "unknown"}`,
    );
    this.name = "ManifestBackedParquetDivergenceError";
    this.code = "MANIFEST_BACKED_DESTINATION_DIVERGENCE";
    this.plan = plan;
  }
}

function loadManifestEntriesForPrune(
  rcloneBin,
  manifestRootPath,
  retryOptions = null,
  listedEntries = null,
) {
  const entries = listedEntries || rcloneLsjsonRecursive(rcloneBin, manifestRootPath, {
    hash: false,
    retryOptions,
  });
  return entries
    .map((entry) => pathFromLsjsonEntry(entry))
    .filter((relPath) => relPath.endsWith("manifest.json"))
    .sort()
    .map((relativePath) => ({
      relative_path: relativePath,
      text: rcloneCat(
        rcloneBin,
        joinTargetPath(manifestRootPath, relativePath),
        retryOptions,
      ),
    }));
}

function loadActualParquetEntriesForPrune(
  rcloneBin,
  destUnitPath,
  retryOptions = null,
  listedEntries = null,
) {
  return (listedEntries || rcloneLsjsonRecursive(rcloneBin, destUnitPath, {
    hash: false,
    retryOptions,
  }))
    .map((entry) => ({ ...entry, Path: pathFromLsjsonEntry(entry) }))
    .filter((entry) => entry.Path.endsWith(".parquet"));
}

export function pruneStaleParquetForUnit({
  rcloneBin,
  manifestRootPath,
  destUnitPath,
  unitRelativePath,
  dryRun = false,
  readListRetryOptions = null,
  manifestReadListRetryOptions = readListRetryOptions,
  destinationReadListRetryOptions = readListRetryOptions,
  deleteRetryOptions = null,
  manifestEntries = null,
  destinationManifestEntries = null,
  actualFileEntries = null,
  deleteFile = rcloneDeleteFile,
} = {}) {
  const needsDestinationListing = destinationManifestEntries === null
    || actualFileEntries === null;
  const destinationListing = needsDestinationListing
    ? rcloneLsjsonRecursive(rcloneBin, destUnitPath, {
      hash: false,
      retryOptions: destinationReadListRetryOptions,
    })
    : null;
  const authoritativeListing = manifestEntries === null
    && manifestRootPath === destUnitPath
    && manifestReadListRetryOptions === destinationReadListRetryOptions
    ? destinationListing
    : null;
  const plan = buildStaleParquetPrunePlan({
    unit_relative_path: unitRelativePath,
    manifest_entries: manifestEntries || loadManifestEntriesForPrune(
      rcloneBin, manifestRootPath, manifestReadListRetryOptions, authoritativeListing,
    ),
    destination_manifest_entries: destinationManifestEntries
      || loadManifestEntriesForPrune(
        rcloneBin, destUnitPath, destinationReadListRetryOptions, destinationListing,
      ),
    actual_file_entries: actualFileEntries || loadActualParquetEntriesForPrune(
      rcloneBin, destUnitPath, destinationReadListRetryOptions, destinationListing,
    ),
  });

  if (plan.manifest_backed_divergence_count > 0) {
    throw new ManifestBackedParquetDivergenceError(plan);
  }

  const deletedPaths = [];
  const dryRunPaths = [];
  for (const relPath of plan.stale_relative_paths) {
    if (dryRun) {
      dryRunPaths.push(relPath);
      continue;
    }
    deleteFile(
      rcloneBin,
      joinTargetPath(destUnitPath, relPath),
      deleteRetryOptions,
    );
    deletedPaths.push(relPath);
  }

  return {
    prune_attempted: true,
    prune_skipped: false,
    unit_relative_path: plan.unit_relative_path,
    manifest_count: plan.manifest_count,
    destination_manifest_count: plan.destination_manifest_count,
    manifest_referenced_parquet_count: plan.manifest_referenced_parquet_count,
    destination_manifest_referenced_parquet_count:
      plan.destination_manifest_referenced_parquet_count,
    actual_destination_parquet_count: plan.actual_destination_parquet_count,
    manifest_backed_divergence_count: 0,
    prune_deleted_count: deletedPaths.length,
    prune_dry_run_delete_count: dryRunPaths.length,
    prune_error_count: 0,
    pruned_relative_paths: dryRun ? dryRunPaths : deletedPaths,
    pruned_relative_paths_truncated: false,
  };
}
