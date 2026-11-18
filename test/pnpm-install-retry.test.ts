import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import test from "node:test";

const script = resolve(".github/actions/setup-pnpm/install-dependencies.sh");

function exercise(message: string, successAt = 0, code = 1) {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-install-retry-"));
  try {
    writeFileSync(
      join(root, "pnpm"),
      `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$TRACE"
count=$(wc -l < "$TRACE")
if [[ "$SUCCESS_AT" -gt 0 && "$count" -ge "$SUCCESS_AT" ]]; then exit 0; fi
printf '%s\\n' "$MESSAGE" >&2
exit "$EXIT_CODE"
`,
      { mode: 0o755 },
    );
    writeFileSync(join(root, "sleep"), '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$WAITS"\n', {
      mode: 0o755,
    });
    const trace = join(root, "trace");
    const waits = join(root, "waits");
    writeFileSync(waits, "");
    const result = spawnSync("bash", [script], {
      cwd: root,
      encoding: "utf8",
      timeout: 10_000,
      env: {
        ...process.env,
        PATH: root + delimiter + process.env.PATH,
        TRACE: trace,
        WAITS: waits,
        MESSAGE: message,
        SUCCESS_AT: String(successAt),
        EXIT_CODE: String(code),
      },
    });
    assert.ifError(result.error);
    return {
      status: result.status,
      calls: readFileSync(trace, "utf8").trim().split("\n"),
      waits: readFileSync(waits, "utf8").trim(),
      output: result.stdout,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("frozen-lockfile contract failures stop after one real subprocess", () => {
  for (const code of ["OUTDATED_LOCKFILE", "NO_LOCKFILE", "LOCKFILE_CONFIG_MISMATCH"]) {
    const result = exercise(` ERR_PNPM_${code} Cannot perform frozen install`, 0, 7);
    assert.equal(result.status, 7);
    assert.deepEqual(result.calls, ["install --frozen-lockfile"]);
    assert.equal(result.waits, "");
    assert.match(result.output, new RegExp(code));
  }
});

test("transient and unknown failures retain bounded retries and backoff", () => {
  for (const message of [
    "ECONNRESET",
    "unclassified failure",
    "ERR_PNPM_OUTDATED_LOCKFILE_EXTRA",
  ]) {
    const result = exercise(message);
    assert.equal(result.status, 1);
    assert.equal(result.calls.length, 3);
    assert.equal(result.waits, "10\n20");
  }
  const recovered = exercise("ETIMEDOUT", 2);
  assert.equal(recovered.status, 0);
  assert.equal(recovered.calls.length, 2);
  assert.equal(recovered.waits, "10");
  assert.equal(exercise("", 1).calls.length, 1);
});

test("interrupted installs preserve the exit status without another attempt", () => {
  for (const code of [130, 143]) {
    const result = exercise("interrupted", 0, code);
    assert.equal(result.status, code);
    assert.equal(result.calls.length, 1);
    assert.equal(result.waits, "");
  }
});
