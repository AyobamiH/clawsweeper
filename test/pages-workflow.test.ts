import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("Pages reruns upload and deploy a run-attempt-scoped artifact", () => {
  const workflow = readFileSync(".github/workflows/pages.yml", "utf8").replace(/\r\n/g, "\n");

  assert.match(workflow, /PAGES_ARTIFACT_NAME: github-pages-\$\{\{ github\.run_attempt \}\}/);
  assert.match(
    workflow,
    /uses: actions\/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3\.2\.0\n\s+with:\n(?:\s+.+\n)*?\s+owner: AyobamiH\n\s+repositories: clawsweeper\n\s+permission-administration: write/,
  );
  assert.match(
    workflow,
    /uses: actions\/configure-pages@v6\n\s+with:\n\s+token: \$\{\{ steps\.pages-token\.outputs\.token \}\}\n\s+enablement: true/,
  );
  assert.equal(workflow.match(/\$\{\{ env\.PAGES_ARTIFACT_NAME \}\}/g)?.length, 2);
  assert.match(
    workflow,
    /uses: actions\/upload-pages-artifact@v5\n\s+with:\n\s+name: \$\{\{ env\.PAGES_ARTIFACT_NAME \}\}/,
  );
  assert.match(
    workflow,
    /uses: actions\/deploy-pages@v5\n\s+with:\n\s+artifact_name: \$\{\{ env\.PAGES_ARTIFACT_NAME \}\}/,
  );
});
