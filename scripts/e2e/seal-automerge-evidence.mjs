#!/usr/bin/env node
/**
 * Seal the unreduced E2E evidence in an owner-mounted, dedicated local vault.
 * A provider artifact upload may fail; this seal must not.
 * The independent host controller verifies every file after the runner exits.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AUTOMERGE_E2E_SCENARIOS } from "../../test/e2e/automerge/run.mjs";
import { AUTOMERGE_E2E_FIXTURES } from "../../test/e2e/automerge/target-fixtures.mjs";

const MAX_FILES = 12_000;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const SHA = /^[a-f0-9]{40}$/;
const POSITIVE_INTEGER = /^[1-9][0-9]*$/;

function requireValue(flag) {
  const index = process.argv.indexOf(flag);
  if (index < 0 || !process.argv[index + 1] || process.argv[index + 1].startsWith("--")) {
    throw new Error("required argument missing: " + flag);
  }
  return process.argv[index + 1];
}

function digest(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function mustDirectory(dir) {
  const info = fs.lstatSync(dir);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error("evidence directory is not an owned directory");
  }
}

function syncDirectory(dir) {
  const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function writeSynced(file, bytes) {
  const fd = fs.openSync(
    file,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
    0o644,
  );
  try {
    const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    let offset = 0;
    while (offset < data.length) {
      offset += fs.writeSync(fd, data, offset, data.length - offset);
    }
    fs.fchmodSync(fd, 0o644);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function walk(root) {
  const files = [];
  const directories = [root];
  let totalBytes = 0;
  for (let i = 0; i < directories.length; i += 1) {
    const dir = directories[i];
    mustDirectory(dir);
    for (const name of fs.readdirSync(dir).sort()) {
      const full = path.join(dir, name);
      const info = fs.lstatSync(full);
      if (info.isSymbolicLink()) {
        throw new Error("evidence contains a symbolic link");
      }
      if (info.isDirectory()) {
        directories.push(full);
      } else if (info.isFile()) {
        if (info.size > MAX_FILE_BYTES) {
          throw new Error("evidence file exceeds bounded size");
        }
        totalBytes += info.size;
        if (totalBytes > MAX_TOTAL_BYTES || files.length >= MAX_FILES) {
          throw new Error("evidence capacity exceeded");
        }
        files.push({
          full,
          relative: path.relative(root, full).split(path.sep).join("/"),
          size: info.size,
        });
      } else {
        throw new Error("evidence contains an unsupported file type");
      }
    }
  }
  return { files: files.sort((a, b) => a.relative.localeCompare(b.relative)), totalBytes };
}

function copyPinnedFile(src, dest, expectedBytes) {
  const inputFd = fs.openSync(src, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  const outputFd = fs.openSync(
    dest,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
    0o644,
  );
  const hash = crypto.createHash("sha256");
  let total = 0;
  try {
    const info = fs.fstatSync(inputFd);
    if (!info.isFile() || info.size !== expectedBytes) {
      throw new Error("evidence source changed during collection");
    }
    const buffer = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      const n = fs.readSync(inputFd, buffer, 0, buffer.length, null);
      if (!n) break;
      hash.update(buffer.subarray(0, n));
      let offset = 0;
      while (offset < n) {
        offset += fs.writeSync(outputFd, buffer, offset, n - offset);
      }
      total += n;
    }
    fs.fchmodSync(outputFd, 0o644);
    fs.fsyncSync(outputFd);
    if (total !== expectedBytes || fs.fstatSync(inputFd).size !== expectedBytes) {
      throw new Error("evidence source size drifted");
    }
  } finally {
    fs.closeSync(inputFd);
    fs.closeSync(outputFd);
  }
  const sha = hash.digest("hex");
  if (digest(fs.readFileSync(dest)) !== sha) {
    throw new Error("evidence copied bytes failed independent readback");
  }
  return sha;
}

function main() {
  const input = path.resolve(requireValue("--input"));
  const vault = path.resolve(requireValue("--vault"));
  const head = requireValue("--expected-head");
  const runId = process.env.GITHUB_RUN_ID;
  const attempt = process.env.GITHUB_RUN_ATTEMPT;
  const checkout = process.env.GITHUB_SHA;
  if (
    !SHA.test(head) ||
    !SHA.test(checkout ?? "") ||
    !POSITIVE_INTEGER.test(runId ?? "") ||
    !POSITIVE_INTEGER.test(attempt ?? "")
  ) {
    throw new Error("exact GitHub run/source identity is required");
  }
  if (AUTOMERGE_E2E_SCENARIOS.length !== 14 || AUTOMERGE_E2E_FIXTURES.length !== 2) {
    throw new Error("the unreduced scenario inventory changed");
  }
  mustDirectory(input);
  mustDirectory(vault);
  fs.accessSync(vault, fs.constants.W_OK | fs.constants.X_OK);
  const { files, totalBytes } = walk(input);
  const expected = [];
  const failed = [];
  for (const fixture of AUTOMERGE_E2E_FIXTURES) {
    for (const scenario of AUTOMERGE_E2E_SCENARIOS) {
      expected.push({ fixture, scenario });
      const file = path.join(input, fixture, scenario, "summary.json");
      try {
        const info = fs.lstatSync(file);
        if (!info.isFile() || info.isSymbolicLink()) throw new Error("not regular");
        const value = JSON.parse(fs.readFileSync(file, "utf8"));
        if (value.status !== "passed" || value.fixture !== fixture || value.scenario !== scenario) {
          failed.push(fixture + "/" + scenario);
        }
      } catch {
        failed.push(fixture + "/" + scenario);
      }
    }
  }
  if (expected.length !== 28) throw new Error("incomplete expected fixture matrix");
  const name = "run-" + runId + "-attempt-" + attempt;
  const partial = path.join(vault, "." + name + ".partial");
  const final = path.join(vault, name);
  if (fs.existsSync(final) || fs.existsSync(partial)) {
    throw new Error("prior proof intent exists; reconcile instead of overwriting");
  }
  fs.mkdirSync(partial, { mode: 0o755 });
  fs.chmodSync(partial, 0o755);
  const manifest = [];
  const folders = new Set([partial]);
  for (const file of files) {
    const dest = path.join(partial, file.relative);
    const dir = path.dirname(dest);
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    // Retain the 0700 owner-only receipt parent, but permit a distinct
    // non-root runner UID to write evidence readable by the host verifier.
    for (let parent = dir; parent !== partial; parent = path.dirname(parent)) {
      if (!parent.startsWith(partial + path.sep)) {
        throw new Error("evidence path escaped the private run leaf");
      }
      fs.chmodSync(parent, 0o755);
      folders.add(parent);
    }
    const sha256 = copyPinnedFile(file.full, dest, file.size);
    manifest.push({ path: file.relative, size: file.size, sha256 });
  }
  const manifestBytes = Buffer.from(
    JSON.stringify(
      {
        schema: "clawsweeper.e2e-artifact-manifest.v1",
        source_head: head,
        files: manifest,
      },
      null,
      2,
    ) + "\n",
  );
  writeSynced(path.join(partial, "manifest.json"), manifestBytes);
  const passed = failed.length === 0;
  const receipt = {
    schema: "clawsweeper.e2e-local-seal.v1",
    at_utc: new Date().toISOString(),
    github_run_id: Number(runId),
    github_attempt: Number(attempt),
    source_head_sha: head,
    checkout_sha: checkout,
    scenario_count: expected.length - failed.length,
    expected_cases: 28,
    missing_or_failed: failed,
    file_count: manifest.length,
    bytes: totalBytes,
    manifest_sha256: digest(manifestBytes),
    verdict: passed ? "SEALED_28_CASES" : "NOT_VERIFIED",
  };
  const receiptBytes = Buffer.from(JSON.stringify(receipt, null, 2) + "\n");
  writeSynced(path.join(partial, "receipt.json"), receiptBytes);
  writeSynced(path.join(partial, "receipt.sha256"), digest(receiptBytes) + "  receipt.json\n");
  for (const dir of [...folders].sort((a, b) => b.length - a.length)) {
    syncDirectory(dir);
  }
  syncDirectory(partial);
  if (passed) {
    fs.renameSync(partial, final);
    syncDirectory(vault);
  }
  process.stdout.write(
    JSON.stringify({
      verdict: receipt.verdict,
      cases: receipt.scenario_count,
      files: receipt.file_count,
      receipt_sha256: digest(receiptBytes),
    }) + "\n",
  );
  if (!passed) process.exitCode = 5;
}

try {
  main();
} catch (error) {
  process.stderr.write(
    "automerge E2E evidence sealing failed: " +
      (error instanceof Error ? error.message : "unknown") +
      "\n",
  );
  process.exitCode = 1;
}
