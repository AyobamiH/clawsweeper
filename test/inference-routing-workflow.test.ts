import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("exact-review workflow resolves inference before setup and keeps broad Cloudflare token out", () => {
  const source = readFileSync(".github/workflows/sweep.yml", "utf8");
  assert.match(source, /name: Resolve inference route/);
  assert.match(
    source,
    /CLAWSWEEPER_INFERENCE_POLICY: \$\{\{ fromJSON\(steps\.live-item\.outputs\.decision\)\.inferencePolicy \|\| vars\.CLAWSWEEPER_INFERENCE_POLICY \|\| 'auto' \}\}/,
  );
  assert.match(
    source,
    /CLAWSWEEPER_WORKERS_AI_MODEL: \$\{\{ vars\.CLAWSWEEPER_WORKERS_AI_MODEL \|\| '@cf\/zai-org\/glm-5\.3' \}\}/,
  );
  assert.match(
    source,
    /CLOUDFLARE_WORKERS_AI_TOKEN: \$\{\{ secrets\.CLOUDFLARE_WORKERS_AI_TOKEN \}\}/,
  );
  assert.doesNotMatch(
    source,
    /CLOUDFLARE_API_TOKEN: \$\{\{ secrets\.CLOUDFLARE_API_TOKEN \}\}[\s\S]{0,1200}name: Review exact event item/,
  );
  assert.match(source, /CLAWSWEEPER_RUNNER=\$runner/);
  assert.match(source, /CLAWSWEEPER_OPENCLAW_MODEL=\$model/);
  assert.match(source, /CLAWSWEEPER_OPENCLAW_PROVIDERS_JSON=\$providers_json/);
  assert.match(source, /steps\.inference-route\.outputs\.runner == 'openclaw'/);
  assert.match(source, /reviewOptions\.inference_policy/);
  assert.match(source, /inferencePolicy:/);
  assert.ok(
    source.indexOf("name: Resolve inference route") <
      source.indexOf("uses: ./.github/actions/setup-codex"),
  );
});
