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
import { createServer } from "node:http";
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
  type RepairArtifactGitClient,
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

async function gitStore(t: TestContext) {
  const root = sandbox(t);
  const remote = path.join(root, "remote.git");
  const seed = path.join(root, "seed");
  const state = path.join(root, "state");
  const git = (cwd: string, ...args: string[]) =>
    execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git(root, "init", "--bare", remote);
  git(root, "clone", remote, seed);
  for (const [key, value] of [
    ["user.name", "repair-artifact-test"],
    ["user.email", "test@example.invalid"],
    ["commit.gpgsign", "false"],
  ])
    git(seed, "config", key!, value!);
  mkdirSync(path.join(seed, "jobs"));
  mkdirSync(path.join(seed, "results"));
  writeFileSync(path.join(seed, "jobs", "seed.md"), "seed\n");
  writeFileSync(path.join(seed, "results", "unrelated.json"), '{"preserved":true}\n');
  git(seed, "add", ".");
  git(seed, "commit", "-m", "seed private operational state");
  git(seed, "push", "origin", "HEAD:state");
  git(remote, "symbolic-ref", "HEAD", "refs/heads/state");
  git(root, "clone", "--no-local", remote, state);
  git(state, "config", "commit.gpgsign", "false");
  git(state, "sparse-checkout", "init", "--cone");
  git(state, "sparse-checkout", "set", "jobs");
  const requests: string[] = [];
  let denied = false;
  let ticket: Record<string, unknown> | undefined;
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks);
    const expected = "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
    if (request.headers["x-clawsweeper-exact-review-signature"] !== expected) {
      response.writeHead(401);
      response.end('{"ok":false,"error":"invalid_signature"}');
      return;
    }
    const payload = JSON.parse(body.toString("utf8"));
    requests.push(request.url!);
    if (denied) {
      response.writeHead(403);
      response.end('{"ok":false,"error":"denied"}');
      return;
    }
    if (request.url?.endsWith("/acquire")) {
      ticket = {
        ticketId: payload.ticket_id,
        owner: payload.owner,
        state: "leased",
        leaseToken: "synthetic-repair-artifact-ticket",
        leaseGeneration: 1,
        leaseExpiresAt: Date.now() + 60_000,
        leaseDeadlineAt: Date.now() + 120_000,
        seq: 1,
      };
    }
    response.setHeader("content-type", "application/json");
    response.end(
      JSON.stringify(
        request.url?.endsWith("/release") ? { ok: true, released: true } : { ok: true, ticket },
      ),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const client: RepairArtifactGitClient = {
    transport: "git-results",
    stateDirectory: state,
    expectedOrigin: remote,
    env: {
      ...process.env,
      CLAWSWEEPER_STATE_COORDINATOR_ENABLED: "1",
      CLAWSWEEPER_STATE_COORDINATOR_URL: `http://127.0.0.1:${address.port}`,
      CLAWSWEEPER_STATE_COORDINATOR_SECRET: secret,
      CLAWSWEEPER_PUBLISH_BRANCH: "state",
    },
  };
  const advance = (mutate: () => void) => {
    git(seed, "fetch", "origin", "state");
    git(seed, "checkout", "--detach", "FETCH_HEAD");
    mutate();
    git(seed, "add", "-A");
    git(seed, "commit", "-m", "test independent state update");
    git(seed, "push", "origin", "HEAD:state");
    return git(seed, "rev-parse", "HEAD");
  };
  return {
    root,
    remote,
    seed,
    state,
    git,
    client,
    requests,
    advance,
    deny: (value: boolean) => {
      denied = value;
    },
    initial: git(remote, "rev-parse", "state"),
  };
}

test(
  "Git results use the existing coordinated normal publisher and restore an immutable commit",
  { timeout: 60_000 },
  async (t) => {
    const store = await gitStore(t);
    const source = files(store.root);
    const preflight = await preflightRepairArtifacts({ binding: bound, client: store.client });
    assert.match(preflight.state_commit!, /^[0-9a-f]{40}$/);
    assert.match(preflight.preflight_path, /^results\/repair-artifacts\/v1\//);
    const published = await publishRepairArtifacts({
      binding: bound,
      client: store.client,
      root: source,
    });
    assert.equal(store.git(store.remote, "rev-parse", "state"), published.state_commit);
    assert.ok(store.requests.includes("/internal/state-writer/acquire"));
    assert.ok(store.requests.includes("/internal/state-writer/heartbeat"));
    assert.ok(store.requests.includes("/internal/state-writer/release"));
    const changed = store
      .git(
        store.remote,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        published.state_commit!,
      )
      .split("\n");
    assert.ok(
      changed.every((name) =>
        name.startsWith(published.manifest_path.split("/manifests/")[0]! + "/"),
      ),
    );
    assert.equal(
      store.git(store.remote, "show", published.state_commit + ":results/unrelated.json"),
      '{"preserved":true}',
    );
    const again = await publishRepairArtifacts({
      binding: bound,
      client: store.client,
      root: source,
    });
    assert.equal(again.state_commit, published.state_commit);
    store.advance(() =>
      writeFileSync(path.join(store.seed, "results/unrelated.json"), '{"advanced":true}\n'),
    );
    const destination = path.join(store.root, "restored", "runs");
    const restored = await restoreRepairArtifacts({
      binding: bound,
      client: store.client,
      root: destination,
      reference: published,
    });
    assert.equal(restored.verified, true);
    assert.equal(restored.state_commit, published.state_commit);
    assert.deepEqual(
      readFileSync(path.join(destination, "cluster/result.json")),
      readFileSync(path.join(source, "cluster/result.json")),
    );
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
  },
);

test(
  "Git restore refuses foreign commits, tampered blobs and symbolic tree entries without partial output",
  { timeout: 60_000 },
  async (t) => {
    const store = await gitStore(t);
    const published = await publishRepairArtifacts({
      binding: bound,
      client: store.client,
      root: files(store.root),
    });
    const destination = path.join(store.root, "restored", "runs");
    const options = { binding: bound, client: store.client, root: destination };
    await assert.rejects(
      restoreRepairArtifacts({ ...options, reference: { ...published, state_commit: "main" } }),
      /reference/,
    );
    await assert.rejects(
      restoreRepairArtifacts({
        ...options,
        reference: { ...published, state_commit: store.initial },
      }),
      /file mode or size/,
    );
    await assert.rejects(
      restoreRepairArtifacts({
        ...options,
        binding: { ...bound, run_id: "999" },
        reference: published,
      }),
      /reference/,
    );
    const manifest = JSON.parse(
      store.git(store.remote, "show", published.state_commit + ":" + published.manifest_path),
    );
    const entry = manifest.files.find((item: { bytes: number }) => item.bytes > 0);
    const blobPath = published.manifest_path.split("/manifests/")[0] + "/files/" + entry.digest;
    const corrupt = store.advance(() =>
      writeFileSync(path.join(store.seed, blobPath), Buffer.alloc(entry.bytes, 88)),
    );
    await assert.rejects(
      restoreRepairArtifacts({ ...options, reference: { ...published, state_commit: corrupt } }),
      /file digest or size/,
    );
    assert.equal(existsSync(destination), false);
    assert.deepEqual(readdirSync(path.dirname(destination)), []);
    const symbolic = store.advance(() => {
      rmSync(path.join(store.seed, blobPath));
      symlinkSync("/etc/passwd", path.join(store.seed, blobPath));
    });
    await assert.rejects(
      restoreRepairArtifacts({ ...options, reference: { ...published, state_commit: symbolic } }),
      /file mode or size/,
    );
    assert.equal(existsSync(destination), false);
  },
);

test(
  "Git preflight fails closed on disabled or denied coordination and rejected normal pushes",
  { timeout: 60_000 },
  async (t) => {
    const store = await gitStore(t);
    store.git(store.state, "config", "remote.origin.pushurl", path.join(store.root, "foreign.git"));
    await assert.rejects(
      preflightRepairArtifacts({ binding: bound, client: store.client }),
      /origin differs/,
    );
    assert.equal(store.requests.length, 0);
    store.git(store.state, "config", "--unset", "remote.origin.pushurl");
    const disabled = {
      ...store.client,
      env: { ...store.client.env, CLAWSWEEPER_STATE_COORDINATOR_ENABLED: "0" },
    };
    await assert.rejects(
      preflightRepairArtifacts({ binding: bound, client: disabled }),
      /requires the existing state writer coordinator/,
    );
    assert.equal(store.requests.length, 0);
    store.deny(true);
    await assert.rejects(
      preflightRepairArtifacts({ binding: bound, client: store.client }),
      /publication failed/,
    );
    assert.equal(store.git(store.remote, "rev-parse", "state"), store.initial);
    store.deny(false);
    const hook = path.join(store.remote, "hooks", "pre-receive");
    writeFileSync(hook, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
    await assert.rejects(
      preflightRepairArtifacts({ binding: bound, client: store.client }),
      /publication failed/,
    );
    assert.equal(store.git(store.remote, "rev-parse", "state"), store.initial);
    rmSync(hook);
    const recovered = await preflightRepairArtifacts({ binding: bound, client: store.client });
    assert.equal(recovered.verified, true);
    assert.equal(store.git(store.remote, "rev-parse", "state"), recovered.state_commit);
  },
);
