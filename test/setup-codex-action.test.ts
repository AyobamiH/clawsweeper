import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { parse } from "yaml";

test(
  "scanner bootstrap refuses a corrupt download before extraction or execution",
  { skip: process.platform === "win32" },
  () => {
    const script = readFileSync(".github/actions/setup-review-tools/install.sh", "utf8");
    const root = mkdtempSync(join(tmpdir(), "clawsweeper-scanner-install-test-"));
    const bin = join(root, "bin");
    const temporary = join(root, "temporary");
    const invoked = join(root, "extracted");
    for (const dir of [bin, temporary, join(root, "checkout")]) mkdirSync(dir);
    writeFileSync(
      join(bin, "uname"),
      '#!/bin/sh\nif [ "$1" = "-s" ]; then echo Linux; else echo x86_64; fi\n',
      { mode: 0o755 },
    );
    writeFileSync(
      join(bin, "curl"),
      '#!/bin/sh\nwhile [ "$1" != "--output" ]; do shift; done\nprintf corrupt > "$2"\n',
      { mode: 0o755 },
    );
    if (process.platform === "darwin")
      writeFileSync(join(bin, "sha256sum"), '#!/bin/sh\nexec /usr/bin/shasum -a 256 "$@"\n', {
        mode: 0o755,
      });
    writeFileSync(
      join(bin, "tar"),
      `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(invoked)}, 'unexpected');`,
      { mode: 0o755 },
    );
    try {
      const result = spawnSync("/bin/bash", ["-c", script], {
        encoding: "utf8",
        env: {
          PATH: `${bin}:/usr/bin:/bin`,
          RUNNER_TEMP: temporary,
          GITHUB_WORKSPACE: join(root, "checkout"),
          GITHUB_PATH: join(root, "github-path"),
        },
      });
      assert.notEqual(result.status, 0);
      assert.match(result.stdout + result.stderr, /FAILED|did NOT match/);
      assert.equal(existsSync(invoked), false);
      assert.equal(existsSync(join(root, "github-path")), false);
      assert.deepEqual(readdirSync(temporary), []);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);

type CompositeAction = {
  runs?: {
    steps?: Array<{ if?: string; name?: string; run?: string }>;
  };
};

test(
  "hosted Linux sandbox preflight propagates Codex startup failures",
  { skip: process.platform === "win32" ? "requires Bash" : false },
  () => {
    const action = parse(readFileSync(".github/actions/setup-codex/action.yml", "utf8")) as
      | CompositeAction
      | undefined;
    const step = action?.runs?.steps?.find(
      (candidate) => candidate.name === "Enable Linux user namespaces for bubblewrap",
    );

    assert.equal(step?.if, "${{ runner.os == 'Linux' && runner.environment == 'github-hosted' }}");
    assert.ok(step?.run);

    const root = mkdtempSync(join(tmpdir(), "clawsweeper-codex-sandbox-preflight-"));
    const bin = join(root, "bin");
    const codex = join(bin, "codex");
    const sysctl = join(bin, "sysctl");

    try {
      mkdirSync(bin);
      writeFileSync(sysctl, "#!/bin/bash\nexit 1\n", { mode: 0o755 });
      writeFileSync(codex, "#!/bin/bash\nexit 23\n", { mode: 0o755 });

      const result = spawnSync("/bin/bash", ["-c", step.run], {
        cwd: root,
        env: {
          ...process.env,
          GITHUB_WORKSPACE: root,
          PATH: `${bin}:/usr/bin:/bin`,
        },
        encoding: "utf8",
      });

      assert.equal(result.status, 23, result.stderr);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);


test("setup-codex defaults to ChatGPT auth and fails closed away from API billing", () => {
  const action = parse(readFileSync(".github/actions/setup-codex/action.yml", "utf8")) as
    | (CompositeAction & { inputs?: Record<string, { default?: string }> })
    | undefined;

  assert.equal(action?.inputs?.["auth-mode"]?.default, "chatgpt");

  const steps = action?.runs?.steps ?? [];
  const chatgpt = steps.find((step) => step.name === "Authenticate Codex with ChatGPT");
  const apiKey = steps.find((step) => step.name === "Authenticate Codex with API key");
  const proxy = steps.find((step) => step.name === "Authenticate Codex through Responses proxy");

  assert.equal(chatgpt?.if, "${{ inputs['auth-mode'] == 'chatgpt' }}");
  assert.match(chatgpt?.run ?? "", /CLAWSWEEPER_CODEX_AUTH_JSON/);
  assert.match(chatgpt?.run ?? "", /Logged in using ChatGPT/);
  assert.match(chatgpt?.run ?? "", /env -u OPENAI_API_KEY -u CODEX_API_KEY -u PROXY_API_KEY/);
  assert.equal(apiKey?.if, "${{ inputs['auth-mode'] == 'api-key' }}");
  assert.equal(proxy?.if, "${{ inputs['auth-mode'] == 'api-proxy' }}");
});


test("ChatGPT mode does not inherit the API-era internal model pin", () => {
  const action = parse(readFileSync(".github/actions/setup-codex/action.yml", "utf8")) as
    | (CompositeAction & { inputs?: Record<string, { default?: string }> })
    | undefined;
  assert.equal(action?.inputs?.["codex-version"]?.default, "0.157.1");

  const steps = action?.runs?.steps ?? [];
  const chatgptConfig = steps.find(
    (step) => step.name === "Configure ChatGPT Codex login boundary",
  );
  const apiModel = steps.find((step) => step.name === "Configure API-backed Codex model");

  assert.equal(chatgptConfig?.if, "${{ inputs['auth-mode'] == 'chatgpt' }}");
  assert.match(chatgptConfig?.run ?? "", /forced_login_method = "chatgpt"/);
  assert.doesNotMatch(chatgptConfig?.run ?? "", /CLAWSWEEPER_INTERNAL_MODEL/);

  assert.equal(
    apiModel?.if,
    "${{ inputs['auth-mode'] == 'api-proxy' || inputs['auth-mode'] == 'api-key' }}",
  );
  assert.match(apiModel?.run ?? "", /CLAWSWEEPER_INTERNAL_MODEL/);
});


test("setup-codex exports the login method consumed by review runtime", () => {
  const action = parse(readFileSync(".github/actions/setup-codex/action.yml", "utf8")) as
    | CompositeAction
    | undefined;
  const steps = action?.runs?.steps ?? [];
  const chatgptConfig = steps.find(
    (step) => step.name === "Configure ChatGPT Codex login boundary",
  );
  const apiConfig = steps.find((step) => step.name === "Configure API-backed Codex model");

  assert.match(
    chatgptConfig?.run ?? "",
    /CLAWSWEEPER_CODEX_LOGIN_METHOD=chatgpt/,
  );
  assert.match(apiConfig?.run ?? "", /CLAWSWEEPER_CODEX_LOGIN_METHOD=api/);
});


test("setup-codex exports the selected login method for runtime config", () => {
  const action = parse(readFileSync(".github/actions/setup-codex/action.yml", "utf8")) as
    | CompositeAction
    | undefined;
  const steps = action?.runs?.steps ?? [];
  const chatgptConfig = steps.find(
    (step) => step.name === "Configure ChatGPT Codex login boundary",
  );
  const apiModel = steps.find((step) => step.name === "Configure API-backed Codex model");

  assert.match(
    chatgptConfig?.run ?? "",
    /CLAWSWEEPER_CODEX_LOGIN_METHOD=chatgpt/,
  );
  assert.match(apiModel?.run ?? "", /CLAWSWEEPER_CODEX_LOGIN_METHOD=api/);
});
