import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs, {
  closeSync,
  existsSync,
  ftruncateSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import {
  REPAIR_ARTIFACT_MAX_BYTES,
  preflightRepairArtifacts,
  publishRepairArtifacts,
  repairArtifactBindingFromEnv,
  restoreRepairArtifacts,
  type RepairArtifactBinding,
  type RepairArtifactReference,
} from "../scripts/repair-artifacts.ts";

const secret = "synthetic-repair-transport-secret";
const baseUrl = "https://worker.example";
const bound: RepairArtifactBinding = {
  repository: "AyobamiH/clawsweeper",
  run_id: "42081417908",
  run_attempt: "1",
  workflow_sha: "a".repeat(40),
  job_path: "jobs/AyobamiH/inbox/issue-ayobamih-clawsweeper-68.md",
  phase: "plan",
};
const hash = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

function sandbox(t: TestContext) {
  const root = mkdtempSync(path.join(tmpdir(), "repair-artifacts-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function files(root: string) {
  const source = path.join(root, "source");
  mkdirSync(path.join(source, "cluster", "review"), { recursive: true });
  writeFileSync(path.join(source, "cluster", "result.json"), '{"status":"planned"}\n');
  writeFileSync(path.join(source, "cluster", "worker.stdout.jsonl"), '{"model":"workers-ai"}\n');
  writeFileSync(path.join(source, "cluster", "review", "report.md"), "Validation evidence\n");
  writeFileSync(path.join(source, "cluster", "empty.log"), "");
  return source;
}

/** Exercises the real signing, stat and ranged-download clients without live credentials or writes. */
function blobStore() {
  const blobs = new Map<string, Buffer>();
  const corrupt = new Set<string>();
  const requests: Array<{ operation: string; path: string }> = [];
  const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
    const body = String(init?.body);
    assert.equal(
      new Headers(init?.headers).get("x-clawsweeper-exact-review-signature"),
      "sha256=" + createHmac("sha256", secret).update(body).digest("hex"),
    );
    assert.ok(!body.includes(secret));
    assert.equal(init?.method, "POST");
    const value = JSON.parse(body);
    assert.match(value.path, /^assets\/repair-artifacts\/v1\//);
    const operation = new URL(String(input)).pathname.split("/").at(-1)!;
    requests.push({ operation, path: value.path });
    if (operation === "put") {
      const content = Buffer.from(value.contentBase64, "base64");
      assert.equal(hash(content), value.digest);
      const unchanged = blobs.get(value.path)?.equals(content) ?? false;
      blobs.set(value.path, content);
      return Response.json({ unchanged });
    }
    const content = blobs.get(value.path);
    if (!content) return Response.json({ error: "blob_not_found" }, { status: 404 });
    if (operation === "stat") {
      return Response.json({
        blob: {
          path: value.path,
          bytes: content.length,
          digest: hash(content),
          digestVerified: true,
        },
      });
    }
    assert.equal(operation, "chunk");
    const chunk = Buffer.from(content.subarray(value.offset, value.offset + value.length));
    if (corrupt.has(value.path) && chunk.length) chunk[0] = chunk[0]! ^ 1;
    return new Response(chunk, {
      status: 206,
      headers: {
        "content-range":
          "bytes " + value.offset + "-" + (value.offset + value.length - 1) + "/" + content.length,
      },
    });
  }) as typeof fetch;
  return { blobs, corrupt, requests, client: { baseUrl, webhookSecret: secret, fetch: fetcher } };
}

function replaceManifest(
  store: ReturnType<typeof blobStore>,
  reference: RepairArtifactReference,
  change: (value: any) => void,
) {
  const manifest = JSON.parse(store.blobs.get(reference.manifest_path)!.toString());
  change(manifest);
  const content = Buffer.from(JSON.stringify(manifest) + "\n");
  const digest = hash(content);
  const blobPath = reference.manifest_path.replace(/[0-9a-f]{64}\.json$/, digest + ".json");
  store.blobs.set(blobPath, content);
  return { manifest_path: blobPath, manifest_digest: digest, manifest_bytes: content.length };
}

test("preflight proves signed write, stat and content readback before any repair input", async () => {
  const store = blobStore();
  const result = await preflightRepairArtifacts({ binding: bound, client: store.client });
  assert.equal(result.verified, true);
  assert.equal(store.blobs.size, 1);
  assert.match(result.preflight_path, /\/preflight\/[a-f0-9]{64}\.json$/);
  assert.deepEqual(
    store.requests.map((request) => request.operation),
    ["put", "stat", "chunk"],
  );
  assert.deepEqual(
    await preflightRepairArtifacts({ binding: bound, client: store.client }),
    result,
  );
});

test("preflight refuses unavailable authority without revealing its credential", async () => {
  await assert.rejects(
    preflightRepairArtifacts({
      binding: bound,
      client: {
        baseUrl,
        webhookSecret: secret,
        fetch: (async () =>
          Response.json({ error: "invalid_signature" }, { status: 401 })) as typeof fetch,
      },
    }),
    (error: Error) => error.message.includes("401") && !error.message.includes(secret),
  );
});

test("publish and atomic restore round-trip a complete plan, including empty files, idempotently", async (t) => {
  const root = sandbox(t);
  const source = files(root);
  const store = blobStore();
  const published = await publishRepairArtifacts({
    binding: bound,
    client: store.client,
    root: source,
  });
  assert.equal(published.files, 4);
  assert.deepEqual(
    await publishRepairArtifacts({ binding: bound, client: store.client, root: source }),
    published,
  );
  const destination = path.join(root, "restored", "runs");
  const restored = await restoreRepairArtifacts({
    binding: bound,
    client: store.client,
    root: destination,
    reference: published,
  });
  assert.equal(restored.unchanged, false);
  for (const relative of [
    "cluster/result.json",
    "cluster/worker.stdout.jsonl",
    "cluster/review/report.md",
    "cluster/empty.log",
  ]) {
    assert.deepEqual(
      readFileSync(path.join(destination, relative)),
      readFileSync(path.join(source, relative)),
    );
  }
  assert.equal(
    (
      await restoreRepairArtifacts({
        binding: bound,
        client: store.client,
        root: destination,
        reference: published,
      })
    ).unchanged,
    true,
  );
});

test("execute evidence supports the same independently retrievable transport", async (t) => {
  const root = sandbox(t);
  const store = blobStore();
  const execute = { ...bound, phase: "execute" as const };
  const published = await publishRepairArtifacts({
    binding: execute,
    client: store.client,
    root: files(root),
  });
  const restored = await restoreRepairArtifacts({
    binding: execute,
    client: store.client,
    root: path.join(root, "retrieval"),
    reference: published,
  });
  assert.equal(restored.verified, true);
  assert.match(restored.manifest_path, /\/execute\/manifests\//);
});

test("restore rejects references belonging to another repository, run, attempt, SHA, job or phase", async (t) => {
  const root = sandbox(t);
  const store = blobStore();
  const published = await publishRepairArtifacts({
    binding: bound,
    client: store.client,
    root: files(root),
  });
  const changes = [
    { repository: "other/repository" },
    { run_id: "42081417909" },
    { run_attempt: "2" },
    { workflow_sha: "b".repeat(40) },
    { job_path: "jobs/other/inbox/issue-69.md" },
    { phase: "execute" as const },
  ];
  for (const change of changes) {
    await assert.rejects(
      restoreRepairArtifacts({
        binding: { ...bound, ...change },
        client: store.client,
        root: path.join(root, "refused"),
        reference: published,
      }),
      /expected workflow binding/,
    );
  }
  const foreign = replaceManifest(store, published, (manifest) => {
    manifest.binding.run_id = "42081417909";
  });
  await assert.rejects(
    restoreRepairArtifacts({
      binding: bound,
      client: store.client,
      root: path.join(root, "refused"),
      reference: foreign,
    }),
    /another workflow/,
  );
  assert.equal(existsSync(path.join(root, "refused")), false);
});

test("restore rejects traversal, duplicate paths, conflicting paths and oversized declarations", async (t) => {
  const root = sandbox(t);
  const store = blobStore();
  const published = await publishRepairArtifacts({
    binding: bound,
    client: store.client,
    root: files(root),
  });
  const changes = [
    (manifest: any) => {
      manifest.files[0].path = "../outside";
    },
    (manifest: any) => {
      manifest.files[0].path = "/absolute";
    },
    (manifest: any) => {
      manifest.files[0].path = "C:\\outside";
    },
    (manifest: any) => {
      manifest.files[1].path = manifest.files[0].path;
    },
    (manifest: any) => {
      manifest.files[0].path = "a";
      manifest.files[1].path = "a/b";
    },
    (manifest: any) => {
      manifest.files[0].bytes = REPAIR_ARTIFACT_MAX_BYTES + 1;
    },
    (manifest: any) => {
      manifest.files = Array.from({ length: 513 }, (_, i) => ({
        ...manifest.files[0],
        path: "file-" + i,
      }));
    },
    (manifest: any) => {
      manifest.files[0].type = "symlink";
    },
  ];
  for (const change of changes) {
    const reference = replaceManifest(store, published, change);
    await assert.rejects(
      restoreRepairArtifacts({
        binding: bound,
        client: store.client,
        root: path.join(root, "refused"),
        reference,
      }),
    );
    assert.equal(existsSync(path.join(root, "refused")), false);
  }
});

test("digest tampering or interrupted transfer never exposes a partially restored tree", async (t) => {
  const root = sandbox(t);
  const store = blobStore();
  const published = await publishRepairArtifacts({
    binding: bound,
    client: store.client,
    root: files(root),
  });
  const manifest = JSON.parse(store.blobs.get(published.manifest_path)!.toString());
  const filePath =
    published.manifest_path.split("/manifests/")[0] + "/files/" + manifest.files[2].digest;
  store.corrupt.add(filePath);
  const destination = path.join(root, "target-parent", "runs");
  await assert.rejects(
    restoreRepairArtifacts({
      binding: bound,
      client: store.client,
      root: destination,
      reference: published,
    }),
    /digest mismatch/,
  );
  assert.equal(existsSync(destination), false);
  assert.deepEqual(readdirSync(path.dirname(destination)), []);
  store.corrupt.clear();
  store.blobs.delete(filePath);
  await assert.rejects(
    restoreRepairArtifacts({
      binding: bound,
      client: store.client,
      root: destination,
      reference: published,
    }),
    /remote identity/,
  );
  assert.equal(existsSync(destination), false);
  assert.deepEqual(readdirSync(path.dirname(destination)), []);
});

test("a manifest digest or size mismatch is refused before any destination write", async (t) => {
  const root = sandbox(t);
  const store = blobStore();
  const published = await publishRepairArtifacts({
    binding: bound,
    client: store.client,
    root: files(root),
  });
  store.corrupt.add(published.manifest_path);
  await assert.rejects(
    restoreRepairArtifacts({
      binding: bound,
      client: store.client,
      root: path.join(root, "refused"),
      reference: published,
    }),
    /digest mismatch/,
  );
  await assert.rejects(
    restoreRepairArtifacts({
      binding: bound,
      client: store.client,
      root: path.join(root, "refused"),
      reference: { ...published, manifest_bytes: published.manifest_bytes + 1 },
    }),
    /remote identity/,
  );
  assert.equal(existsSync(path.join(root, "refused")), false);
});

test("publication does not commit a manifest if file readback fails", async (t) => {
  const root = sandbox(t);
  const source = files(root);
  const store = blobStore();
  const sourceDigest = hash(readFileSync(path.join(source, "cluster/result.json")));
  const fetcher = store.client.fetch!;
  store.client.fetch = (async (input, init) => {
    const value = JSON.parse(String(init?.body));
    if (value.path.endsWith("/files/" + sourceDigest)) store.corrupt.add(value.path);
    return fetcher(input, init);
  }) as typeof fetch;
  await assert.rejects(
    publishRepairArtifacts({ binding: bound, client: store.client, root: source }),
    /digest mismatch/,
  );
  assert.ok(![...store.blobs.keys()].some((key) => key.includes("/manifests/")));
});

test("existing differing results and symlinked destinations are preserved and refused", async (t) => {
  const root = sandbox(t);
  const store = blobStore();
  const published = await publishRepairArtifacts({
    binding: bound,
    client: store.client,
    root: files(root),
  });
  const destination = path.join(root, "existing");
  mkdirSync(destination);
  writeFileSync(path.join(destination, "keep.txt"), "existing work");
  await assert.rejects(
    restoreRepairArtifacts({
      binding: bound,
      client: store.client,
      root: destination,
      reference: published,
    }),
    /overwrite/,
  );
  assert.equal(readFileSync(path.join(destination, "keep.txt"), "utf8"), "existing work");
  symlinkSync(destination, path.join(root, "linked"));
  await assert.rejects(
    restoreRepairArtifacts({
      binding: bound,
      client: store.client,
      root: path.join(root, "linked", "runs"),
      reference: published,
    }),
    /unsafe/,
  );
  assert.equal(existsSync(path.join(destination, "runs")), false);
});

test("source symlinks, hard links, special files and oversized files fail before upload", async (t) => {
  const root = sandbox(t);
  const source = files(root);
  const store = blobStore();
  const unsafe = path.join(source, "unsafe");
  symlinkSync(path.join(source, "cluster/result.json"), unsafe);
  await assert.rejects(
    publishRepairArtifacts({ binding: bound, client: store.client, root: source }),
    /symlinks/,
  );
  rmSync(unsafe);
  linkSync(path.join(source, "cluster/result.json"), unsafe);
  await assert.rejects(
    publishRepairArtifacts({ binding: bound, client: store.client, root: source }),
    /singly linked/,
  );
  rmSync(unsafe);
  if (process.platform !== "win32") {
    execFileSync("mkfifo", [unsafe]);
    await assert.rejects(
      publishRepairArtifacts({ binding: bound, client: store.client, root: source }),
      /regular/,
    );
    rmSync(unsafe);
  }
  const fd = openSync(unsafe, "w");
  ftruncateSync(fd, REPAIR_ARTIFACT_MAX_BYTES + 1);
  closeSync(fd);
  await assert.rejects(
    publishRepairArtifacts({ binding: bound, client: store.client, root: source }),
    /exceed bound/,
  );
  assert.equal(store.requests.length, 0);
});

test("environment identity is explicit and missing workflow evidence fails closed", () => {
  const env = {
    GITHUB_REPOSITORY: bound.repository,
    GITHUB_RUN_ID: bound.run_id,
    GITHUB_RUN_ATTEMPT: bound.run_attempt,
    GITHUB_SHA: bound.workflow_sha,
    CLUSTER_JOB_PATH: bound.job_path,
  };
  assert.deepEqual(repairArtifactBindingFromEnv(env, "plan"), bound);
  assert.throws(() => repairArtifactBindingFromEnv({ ...env, GITHUB_SHA: "" }, "plan"), /binding/);
  assert.throws(() => repairArtifactBindingFromEnv(env, "unknown"), /binding/);
});

test("local short writes are rejected before restored artifacts become visible", async (t) => {
  const root = sandbox(t);
  const source = files(root);
  const store = blobStore();
  const published = await publishRepairArtifacts({
    binding: bound,
    client: store.client,
    root: source,
  });
  const payload = readFileSync(path.join(source, "cluster/result.json"));
  const destination = path.join(root, "restored", "runs");
  const originalWrite = fs.writeSync;
  let shortened = false;
  fs.writeSync = ((fd: number, value: string | NodeJS.ArrayBufferView, ...args: unknown[]) => {
    if (
      !shortened &&
      ArrayBuffer.isView(value) &&
      Buffer.from(value.buffer, value.byteOffset, value.byteLength).equals(payload)
    ) {
      shortened = true;
      return originalWrite(fd, payload.subarray(0, payload.length - 1));
    }
    return Reflect.apply(originalWrite, fs, [fd, value, ...args]);
  }) as typeof fs.writeSync;
  syncBuiltinESMExports();
  try {
    await assert.rejects(
      restoreRepairArtifacts({
        binding: bound,
        client: store.client,
        root: destination,
        reference: published,
      }).then((result) => {
        t.diagnostic(
          JSON.stringify({
            wrongly_verified: result.verified,
            expected_bytes: payload.length,
            written_bytes: readFileSync(path.join(destination, "cluster/result.json")).length,
          }),
        );
        return result;
      }),
      /written (size|digest) mismatch/,
    );
    assert.equal(shortened, true);
    assert.equal(existsSync(destination), false);
    assert.deepEqual(readdirSync(path.dirname(destination)), []);
  } finally {
    fs.writeSync = originalWrite;
    syncBuiltinESMExports();
  }
});
