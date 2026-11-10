import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, mkdir, rm } from "node:fs/promises";
import { execFileSync, spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
const script = path.resolve(".github/actions/setup-review-tools/install.sh");
async function fixture(t, codes) {
  const root = await mkdtemp(path.join(os.tmpdir(), "csw-scanner-bootstrap-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  await mkdir(bin);
  await writeFile(
    path.join(bin, "curl"),
    `#!/bin/sh\ncount_file="$RUNNER_TEMP/calls"\ncount=0\n[ ! -f "$count_file" ] || count=$(cat "$count_file")\ncount=$((count+1))\nprintf '%s' "$count" > "$count_file"\ncase "$count" in ${codes.map((code, i) => `${i + 1}) exit ${code};;`).join(" ")} *) exit 35;; esac\n`,
  );
  await writeFile(path.join(bin, "sleep"), "#!/bin/sh\nexit 0\n");
  execFileSync("chmod", ["+x", path.join(bin, "curl"), path.join(bin, "sleep")]);
  return {
    root,
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      RUNNER_TEMP: root,
      GITHUB_WORKSPACE: path.resolve("."),
      GITHUB_PATH: path.join(root, "github-path"),
    },
  };
}
test("transient TLS failures are retried exactly three times and refuse without executing unverified archive", async (t) => {
  const { root, env } = await fixture(t, [35, 35, 35]);
  const p = spawnSync("bash", [script], { env, encoding: "utf8" });
  assert.equal(p.status, 1);
  assert.equal(await readFile(path.join(root, "calls"), "utf8"), "3");
  assert.match(p.stderr, /curl_exit=35 category=transient_network/);
  assert.match(p.stderr, /status=refused category=download_unavailable/);
  assert.doesNotMatch(p.stderr, /SSL_ERROR_SYSCALL|token=/);
});
test("permanent HTTP error is not retried", async (t) => {
  const { root, env } = await fixture(t, [22]);
  const p = spawnSync("bash", [script], { env, encoding: "utf8" });
  assert.equal(p.status, 1);
  assert.equal(await readFile(path.join(root, "calls"), "utf8"), "1");
  assert.match(p.stderr, /curl_exit=22 category=http_refused/);
});
test("transient failure followed by permanent failure stops after second attempt", async (t) => {
  const { root, env } = await fixture(t, [35, 22]);
  const p = spawnSync("bash", [script], { env, encoding: "utf8" });
  assert.equal(p.status, 1);
  assert.equal(await readFile(path.join(root, "calls"), "utf8"), "2");
});
