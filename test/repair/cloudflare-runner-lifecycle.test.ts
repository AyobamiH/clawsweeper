import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

function exercise(operation: string, scenario: string, runAttempt = "1") {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cf-lifecycle-"));
  try {
    const bin = path.join(temp, "bin");
    fs.mkdirSync(bin);
    const scripts = {
      npm: `echo "npm $*" >> "$TEST_LOG"
if [ "$TEST_SCENARIO" = preparation-failure ]; then exit 42; fi
exit 0`,
      npx: `echo "npx $*" >> "$TEST_LOG"
cat >/dev/null`,
      sleep: "exit 0",
      gh: `echo "$*" >> "$TEST_LOG"
case "$*" in
  *generate-jitconfig*) echo fixture-jit ;;
  *status*) echo offline ;;
  *'.id'*) echo 123 ;;
esac`,
      curl: `echo "$*" >> "$TEST_LOG"
while [ "$#" -gt 0 ]; do
  case "$1" in --output) output="$2"; shift;; --data-binary) payload="\${2#@}"; shift;; esac
  shift
done
if [ "$TEST_SCENARIO" = cleanup-failure ] && jq -e '.name | endswith("-plan")' "$payload" >/dev/null; then exit 22; fi
printf '{"started":true,"stopped":true}' > "$output"`,
    };
    for (const [name, script] of Object.entries(scripts)) {
      fs.writeFileSync(path.join(bin, name), `#!/usr/bin/env bash\n${script}\n`, { mode: 0o700 });
    }
    const log = path.join(temp, "calls.log");
    const result = spawnSync("bash", [".github/actions/cloudflare-runners/lifecycle.sh"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        RUNNER_OPERATION: operation,
        GH_TOKEN: "fixture",
        CLOUDFLARE_API_TOKEN: "fixture",
        CLOUDFLARE_ACCOUNT_ID: "fixture",
        GITHUB_REPOSITORY: "fixture/repo",
        GITHUB_RUN_ID: "123",
        GITHUB_RUN_ATTEMPT: runAttempt,
        GITHUB_OUTPUT: path.join(temp, "output"),
        TEST_LOG: log,
        TEST_SCENARIO: scenario,
      },
    });
    return {
      status: result.status,
      stderr: result.stderr,
      calls: fs.readFileSync(log, "utf8"),
      outputs: fs.readFileSync(path.join(temp, "output"), "utf8"),
    };
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

test("Cloudflare startup fails within its bounded window when the first runner remains offline", () => {
  const result = exercise("start", "offline");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /bounded startup window/);
  assert.equal(result.calls.match(/generate-jitconfig/g)?.length, 1);
  assert.equal(result.calls.match(/\.status/g)?.length, 18);
});

test("Cloudflare cleanup reuses stable runner identities across workflow attempts", () => {
  const first = exercise("stop", "healthy", "1");
  const retry = exercise("stop", "healthy", "3");
  assert.equal(first.status, 0);
  assert.equal(retry.status, 0);
  const names = (calls: string) =>
    [...calls.matchAll(/csw-[a-f0-9]{16}-(?:plan|execute)/g)].map(([name]) => name);
  assert.deepEqual([...new Set(names(first.calls))], [...new Set(names(retry.calls))]);
  assert.match(first.outputs, /^attempt=1$/m);
  assert.match(retry.outputs, /^attempt=3$/m);
});

test("Cloudflare cleanup attempts both containers and deregistration after the first deletion fails", () => {
  const result = exercise("stop", "cleanup-failure");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /continuing remaining cleanup/);
  assert.equal(result.calls.match(/--request DELETE/g)?.length, 2);
  assert.equal(result.calls.match(/--method DELETE/g)?.length, 2);
});

test("Cloudflare cleanup still deregisters both runners when dependency preparation fails", () => {
  const result = exercise("stop", "preparation-failure");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /continuing GitHub runner deregistration/);
  assert.equal(result.calls.match(/--request DELETE/g)?.length ?? 0, 0);
  assert.equal(result.calls.match(/--method DELETE/g)?.length, 2);
});
