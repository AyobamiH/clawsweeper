#!/usr/bin/env node
/** Bounded, run-bound repair artifacts over the existing authenticated state blob transport. */
import { createHash, randomUUID } from "node:crypto";
import {
  constants,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  renameSync,
  rmSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { publishStateBlob } from "../src/state-blob-client.ts";
import { downloadStateBlob, statStateBlob } from "./worker-blobs.ts";

export const REPAIR_ARTIFACT_MAX_BYTES = 24 * 1024 * 1024;
export const REPAIR_ARTIFACT_MAX_FILES = 512;
const MANIFEST_MAX_BYTES = 256 * 1024;
const DIGEST = /^[0-9a-f]{64}$/;
const ROOT_DEFAULT = ".clawsweeper-repair/runs";

export type RepairArtifactBinding = {
  repository: string;
  run_id: string;
  run_attempt: string;
  workflow_sha: string;
  job_path: string;
  phase: "plan" | "execute";
};
type Client = { baseUrl: string; webhookSecret: string; fetch?: typeof fetch };
type Entry = { path: string; bytes: number; digest: string };
type Manifest = {
  schema_version: 1;
  binding: RepairArtifactBinding;
  files: Entry[];
  total_bytes: number;
};
export type RepairArtifactReference = {
  manifest_path: string;
  manifest_digest: string;
  manifest_bytes: number;
};
type Options = { binding: RepairArtifactBinding; client: Client; root: string };

function digest(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function object(value: unknown, keys: string[], label: string): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== [...keys].sort().join(",")
  ) {
    throw new Error("Invalid repair artifact " + label);
  }
  return value as Record<string, unknown>;
}

function safePath(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !value ||
    value.split("/").length > 16 ||
    value
      .split("/")
      .some((part) => !/^[A-Za-z0-9_.-]{1,128}$/.test(part) || part === "." || part === "..")
  ) {
    throw new Error("Unsafe repair artifact path");
  }
  return value;
}

function binding(value: unknown): RepairArtifactBinding {
  const item = object(
    value,
    ["repository", "run_id", "run_attempt", "workflow_sha", "job_path", "phase"],
    "binding",
  );
  if (
    typeof item.repository !== "string" ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(item.repository) ||
    typeof item.run_id !== "string" ||
    !/^[1-9]\d{0,19}$/.test(item.run_id) ||
    typeof item.run_attempt !== "string" ||
    !/^[1-9]\d{0,5}$/.test(item.run_attempt) ||
    typeof item.workflow_sha !== "string" ||
    !/^[0-9a-f]{40}$/.test(item.workflow_sha) ||
    (item.phase !== "plan" && item.phase !== "execute")
  ) {
    throw new Error("Invalid repair artifact workflow binding");
  }
  const jobPath = safePath(item.job_path);
  if (!jobPath.startsWith("jobs/") || !jobPath.endsWith(".md"))
    throw new Error("Invalid repair job binding");
  return {
    repository: item.repository,
    run_id: item.run_id,
    run_attempt: item.run_attempt,
    workflow_sha: item.workflow_sha,
    job_path: jobPath,
    phase: item.phase,
  };
}

export function repairArtifactBindingFromEnv(
  env: NodeJS.ProcessEnv,
  phase: string,
): RepairArtifactBinding {
  return binding({
    repository: env.GITHUB_REPOSITORY,
    run_id: env.GITHUB_RUN_ID,
    run_attempt: env.GITHUB_RUN_ATTEMPT,
    workflow_sha: env.GITHUB_SHA,
    job_path: env.CLUSTER_JOB_PATH,
    phase,
  });
}

function prefix(value: RepairArtifactBinding): string {
  const item = binding(value);
  return (
    "assets/repair-artifacts/v1/" +
    item.repository +
    "/" +
    item.run_id +
    "/" +
    item.run_attempt +
    "/" +
    item.workflow_sha +
    "/" +
    digest(Buffer.from(item.job_path)) +
    "/" +
    item.phase
  );
}

function client(value: Client): Client {
  let url: URL;
  try {
    url = new URL(value.baseUrl);
  } catch (cause) {
    throw new Error("Repair artifact Worker URL is invalid", { cause });
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !value.webhookSecret
  ) {
    throw new Error("Repair artifact transport requires an HTTPS Worker URL and secret");
  }
  return { ...value, baseUrl: url.href.replace(/\/+$/, "") };
}

/** Reject existing symlink ancestors as well as a symlink final destination. */
function safeDirectory(value: string, create = false): string {
  const absolute = path.resolve(value);
  const parsed = path.parse(absolute);
  if (absolute === parsed.root) throw new Error("Repair artifact root cannot be a filesystem root");
  let current = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep)) {
    current = path.join(current, part);
    try {
      const stat = lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink())
        throw new Error("Repair artifact directory is unsafe");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      if (create) mkdirSync(current, { mode: 0o700 });
    }
  }
  return absolute;
}

function snapshot(rootPath: string): {
  files: Entry[];
  payloads: Map<string, Buffer>;
  total_bytes: number;
} {
  const root = safeDirectory(rootPath);
  if (!existsSync(root)) throw new Error("Repair artifact directory is unavailable");
  const paths: string[] = [];
  function walk(directory: string, relative = "") {
    for (const name of readdirSync(directory).sort()) {
      const relativePath = safePath(relative ? relative + "/" + name : name);
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error("Repair artifacts cannot contain symlinks");
      if (stat.isDirectory()) walk(absolute, relativePath);
      else if (stat.isFile() && stat.nlink === 1) paths.push(relativePath);
      else throw new Error("Repair artifacts require regular, singly linked files");
      if (paths.length > REPAIR_ARTIFACT_MAX_FILES)
        throw new Error("Repair artifact file count exceeds bound");
    }
  }
  walk(root);
  if (!paths.length) throw new Error("Repair artifact directory is empty");
  paths.sort();
  const payloads = new Map<string, Buffer>();
  let total = 0;
  const files = paths.map((relativePath) => {
    const fd = openSync(
      path.join(root, relativePath),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const before = fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1)
        throw new Error("Repair artifact file changed type");
      total += before.size;
      if (!Number.isSafeInteger(total) || total > REPAIR_ARTIFACT_MAX_BYTES)
        throw new Error("Repair artifact bytes exceed bound");
      const content = Buffer.alloc(before.size);
      let offset = 0;
      while (offset < content.length) {
        const count = readSync(fd, content, offset, content.length - offset, null);
        if (!count) throw new Error("Repair artifact file changed during snapshot");
        offset += count;
      }
      const extra = readSync(fd, Buffer.alloc(1), 0, 1, null);
      const after = fstatSync(fd);
      if (
        extra ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs
      ) {
        throw new Error("Repair artifact file changed during snapshot");
      }
      const entry = { path: relativePath, bytes: content.length, digest: digest(content) };
      payloads.set(entry.digest, content);
      return entry;
    } finally {
      closeSync(fd);
    }
  });
  return { files, payloads, total_bytes: total };
}

function parseManifest(content: Buffer, expected: RepairArtifactBinding): Manifest {
  if (content.length > MANIFEST_MAX_BYTES)
    throw new Error("Repair artifact manifest exceeds bound");
  const value = object(
    JSON.parse(content.toString("utf8")),
    ["schema_version", "binding", "files", "total_bytes"],
    "manifest",
  );
  const actualBinding = binding(value.binding);
  if (
    value.schema_version !== 1 ||
    JSON.stringify(actualBinding) !== JSON.stringify(binding(expected))
  ) {
    throw new Error("Repair artifact manifest belongs to another workflow run, job or phase");
  }
  if (
    !Array.isArray(value.files) ||
    !value.files.length ||
    value.files.length > REPAIR_ARTIFACT_MAX_FILES
  ) {
    throw new Error("Repair artifact file count is invalid");
  }
  const seen = new Set<string>();
  let previous = "";
  let total = 0;
  const files: Entry[] = value.files.map((raw) => {
    const item = object(raw, ["path", "bytes", "digest"], "file descriptor");
    const filePath = safePath(item.path);
    if (
      filePath <= previous ||
      seen.has(filePath) ||
      filePath
        .split("/")
        .slice(0, -1)
        .some((_, index, parts) => seen.has(parts.slice(0, index + 1).join("/")))
    ) {
      throw new Error("Repair artifact paths are duplicated, conflicting or unsorted");
    }
    if (
      !Number.isSafeInteger(item.bytes) ||
      Number(item.bytes) < 0 ||
      typeof item.digest !== "string" ||
      !DIGEST.test(item.digest)
    )
      throw new Error("Invalid repair artifact file identity");
    total += Number(item.bytes);
    if (!Number.isSafeInteger(total) || total > REPAIR_ARTIFACT_MAX_BYTES)
      throw new Error("Repair artifact bytes exceed bound");
    previous = filePath;
    seen.add(filePath);
    return { path: filePath, bytes: Number(item.bytes), digest: item.digest };
  });
  if (value.total_bytes !== total)
    throw new Error("Repair artifact manifest total is inconsistent");
  return { schema_version: 1, binding: actualBinding, files, total_bytes: total };
}

async function downloadVerified(
  options: Client,
  blobPath: string,
  bytes: number,
  hash: string,
  destination: string,
) {
  const stat = await statStateBlob({ ...options, blobPath });
  if (
    !stat ||
    stat.path !== blobPath ||
    stat.bytes !== bytes ||
    stat.digest !== hash ||
    !stat.digestVerified
  ) {
    throw new Error("Repair artifact remote identity or size mismatch");
  }
  const result = await downloadStateBlob({
    ...options,
    blobPath,
    destination,
    expected: { bytes, digest: hash },
  });
  if (result.bytes !== bytes || result.digest !== hash)
    throw new Error("Repair artifact download identity mismatch");
  const fd = openSync(
    destination,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const written = fstatSync(fd);
    if (!written.isFile() || written.size !== bytes)
      throw new Error("Repair artifact written size mismatch");
    if (digest(readFileSync(fd)) !== hash)
      throw new Error("Repair artifact written digest mismatch");
  } finally {
    closeSync(fd);
  }
}

async function publishVerified(
  options: Client,
  blobPath: string,
  content: Buffer,
  temporary: string,
) {
  const hash = digest(content);
  await publishStateBlob({
    baseUrl: options.baseUrl,
    webhookSecret: options.webhookSecret,
    ...(options.fetch ? { fetchImpl: options.fetch } : {}),
    path: blobPath,
    content,
  });
  const destination = path.join(temporary, randomUUID());
  try {
    await downloadVerified(options, blobPath, content.length, hash, destination);
  } finally {
    rmSync(destination, { force: true });
  }
}

export async function preflightRepairArtifacts(options: {
  binding: RepairArtifactBinding;
  client: Client;
}) {
  const bound = binding(options.binding);
  const connection = client(options.client);
  const content = Buffer.from(
    JSON.stringify({ schema_version: 1, kind: "repair-artifact-preflight", binding: bound }) + "\n",
  );
  const hash = digest(content);
  const blobPath = prefix(bound) + "/preflight/" + hash + ".json";
  const temporary = mkdtempSync(path.join(tmpdir(), "repair-artifact-preflight-"));
  try {
    await publishVerified(connection, blobPath, content, temporary);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
  return {
    binding: bound,
    preflight_path: blobPath,
    preflight_digest: hash,
    preflight_bytes: content.length,
    verified: true,
  };
}

export async function publishRepairArtifacts(options: Options) {
  const bound = binding(options.binding);
  const connection = client(options.client);
  const inventory = snapshot(options.root);
  const manifest: Manifest = {
    schema_version: 1,
    binding: bound,
    files: inventory.files,
    total_bytes: inventory.total_bytes,
  };
  const content = Buffer.from(JSON.stringify(manifest) + "\n");
  if (content.length > MANIFEST_MAX_BYTES)
    throw new Error("Repair artifact manifest exceeds bound");
  const hash = digest(content);
  const manifestPath = prefix(bound) + "/manifests/" + hash + ".json";
  const temporary = mkdtempSync(path.join(tmpdir(), "repair-artifact-publish-"));
  try {
    for (const [fileDigest, payload] of inventory.payloads) {
      await publishVerified(connection, prefix(bound) + "/files/" + fileDigest, payload, temporary);
    }
    // Publish the manifest only after every file has passed authenticated readback.
    await publishVerified(connection, manifestPath, content, temporary);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
  return {
    binding: bound,
    manifest_path: manifestPath,
    manifest_digest: hash,
    manifest_bytes: content.length,
    files: manifest.files.length,
    total_bytes: manifest.total_bytes,
    verified: true,
  };
}

export async function restoreRepairArtifacts(
  options: Options & { reference: RepairArtifactReference },
) {
  const bound = binding(options.binding);
  const connection = client(options.client);
  const ref = options.reference;
  if (
    !DIGEST.test(ref.manifest_digest) ||
    !Number.isSafeInteger(ref.manifest_bytes) ||
    ref.manifest_bytes < 1 ||
    ref.manifest_bytes > MANIFEST_MAX_BYTES ||
    ref.manifest_path !== prefix(bound) + "/manifests/" + ref.manifest_digest + ".json"
  ) {
    throw new Error("Repair artifact reference does not match the expected workflow binding");
  }
  const root = safeDirectory(options.root);
  const temporary = mkdtempSync(path.join(tmpdir(), "repair-artifact-manifest-"));
  let stage: string | undefined;
  try {
    const manifestFile = path.join(temporary, "manifest.json");
    await downloadVerified(
      connection,
      ref.manifest_path,
      ref.manifest_bytes,
      ref.manifest_digest,
      manifestFile,
    );
    const manifest = parseManifest(readFileSync(manifestFile), bound);
    if (existsSync(root) && readdirSync(root).length) {
      if (JSON.stringify(snapshot(root).files) !== JSON.stringify(manifest.files)) {
        throw new Error("Refusing to overwrite existing repair artifacts");
      }
      return {
        binding: bound,
        ...ref,
        files: manifest.files.length,
        total_bytes: manifest.total_bytes,
        verified: true,
        unchanged: true,
      };
    }
    const parent = safeDirectory(path.dirname(root), true);
    stage = mkdtempSync(path.join(parent, ".repair-artifacts-stage-"));
    for (const file of manifest.files) {
      const destination = path.join(stage, ...file.path.split("/"));
      await downloadVerified(
        connection,
        prefix(bound) + "/files/" + file.digest,
        file.bytes,
        file.digest,
        destination,
      );
    }
    safeDirectory(root);
    if (existsSync(root) && readdirSync(root).length)
      throw new Error("Repair artifact destination changed during restore");
    // Same-filesystem rename exposes the complete verified tree, never partial downloads.
    renameSync(stage, root);
    stage = undefined;
    return {
      binding: bound,
      ...ref,
      files: manifest.files.length,
      total_bytes: manifest.total_bytes,
      verified: true,
      unchanged: false,
    };
  } finally {
    if (stage) rmSync(stage, { recursive: true, force: true });
    rmSync(temporary, { recursive: true, force: true });
  }
}

function writeReceipt(file: string, value: unknown) {
  safeDirectory(path.dirname(file), true);
  if (existsSync(file) && !lstatSync(file).isFile())
    throw new Error("Unsafe repair artifact receipt");
  const temporary = file + ".tmp-" + randomUUID();
  const fd = openSync(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeSync(fd, JSON.stringify(value, null, 2) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(temporary, file);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function appendSafe(file: string | undefined, text: string) {
  if (!file) return;
  const fd = openSync(
    file,
    constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    if (!fstatSync(fd).isFile()) throw new Error("Unsafe workflow output file");
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

async function main() {
  const [operation, ...args] = process.argv.slice(2);
  if (!["preflight", "publish", "restore"].includes(operation ?? ""))
    throw new Error("Expected preflight, publish or restore");
  const { values } = parseArgs({
    args,
    options: { phase: { type: "string" }, root: { type: "string", default: ROOT_DEFAULT } },
  });
  const bound = repairArtifactBindingFromEnv(process.env, values.phase ?? "");
  const connection = {
    baseUrl: process.env.CLAWSWEEPER_STATE_WORKER_URL ?? "",
    webhookSecret: process.env.CLAWSWEEPER_WEBHOOK_SECRET ?? "",
  };
  const options = { binding: bound, client: connection, root: values.root };
  const result =
    operation === "preflight"
      ? await preflightRepairArtifacts(options)
      : operation === "publish"
        ? await publishRepairArtifacts(options)
        : await restoreRepairArtifacts({
            ...options,
            reference: {
              manifest_path: process.env.REPAIR_ARTIFACT_MANIFEST_PATH ?? "",
              manifest_digest: process.env.REPAIR_ARTIFACT_MANIFEST_DIGEST ?? "",
              manifest_bytes: Number(process.env.REPAIR_ARTIFACT_MANIFEST_BYTES),
            },
          });
  const receipt = { operation, ...result, completed_at: new Date().toISOString() };
  const receiptPath = path.resolve(
    ".artifacts",
    "repair-artifacts-" + operation + "-" + bound.phase + ".json",
  );
  writeReceipt(receiptPath, receipt);
  if ("manifest_path" in result) {
    appendSafe(
      process.env.GITHUB_OUTPUT,
      "manifest_path=" +
        result.manifest_path +
        "\nmanifest_digest=" +
        result.manifest_digest +
        "\nmanifest_bytes=" +
        result.manifest_bytes +
        "\n",
    );
  }
  appendSafe(
    process.env.GITHUB_STEP_SUMMARY,
    "\n### Verified repair artifact " +
      operation +
      " (" +
      bound.phase +
      ")\n\n" +
      "Run " +
      bound.run_id +
      ", attempt " +
      bound.run_attempt +
      ", revision \x60" +
      bound.workflow_sha +
      "\x60.\n\n" +
      ("manifest_path" in result
        ? "Authenticated manifest: \x60" +
          result.manifest_path +
          "\x60\n\nSHA-256: \x60" +
          result.manifest_digest +
          "\x60; bytes: " +
          result.manifest_bytes +
          ".\n"
        : "Authenticated write, metadata and content readback succeeded before inference.\n"),
  );
  process.stdout.write(JSON.stringify(receipt) + "\n");
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error: unknown) => {
    const secret = process.env.CLAWSWEEPER_WEBHOOK_SECRET ?? "";
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(
      "repair-artifacts: " + (secret ? message.replaceAll(secret, "<redacted>") : message) + "\n",
    );
    process.exitCode = 1;
  });
}
