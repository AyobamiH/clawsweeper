import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("dashboard deploy synchronizes the exact-review operator secret used by recovery routes", () => {
  const workflow = readFileSync(".github/workflows/dashboard.yml", "utf8").replace(/\r\n/g, "\n");

  assert.match(
    workflow,
    /EXACT_REVIEW_OPERATOR_SECRET: \$\{\{ secrets\.EXACT_REVIEW_OPERATOR_SECRET \|\| secrets\.CLAWSWEEPER_WEBHOOK_SECRET \}\}/,
  );
  assert.match(workflow, /test -n "\$EXACT_REVIEW_OPERATOR_SECRET"/);
  assert.match(
    workflow,
    /"CLAWSWEEPER_APP_PRIVATE_KEY",\n\s+"CLAWSWEEPER_WEBHOOK_SECRET",\n\s+"EXACT_REVIEW_OPERATOR_SECRET",/,
  );
});
