# Tasks

## 1. Role-scoped request rescanning

- [x] 1.1 Add scenario-named V2 conformance regressions for each new or modified history scenario, referencing the delta spec; verify the valid-fence tests fail on the current implementation before any source change. Use known-detectable fixtures and hook shapes verified against the installed SDK.
- [x] 1.2 Cover prompt output carried into chained and repeated context/generate/compaction scans, including newly introduced outside secrets; verify the failing assertions isolate loss of the fence exemption rather than scanner detection failures.
- [x] 1.3 Add negative regression coverage for system-prompt segments and tool output as well as non-user, missing, unknown, differently cased, and non-string roles; verify identical fenced fixtures remain scanned. Preserve per-block boundaries, aggregation, non-text properties, and fail-open behavior in the scenario tests.
- [x] 1.4 Implement a private default-off fence policy through the existing V2 block/array helpers, enabled only by exact user-role selection; reuse the existing user-message redactor and verify every scenario test passes without changes to scanner rules, dependencies, V1, or annotations.
- [x] 1.5 Update README user-message documentation to explain V2 rescan persistence, independent text-block fences, excluded roles, and the accepted synthetic/file/summary user-role limitation; verify statements match the delta and design.

## 2. Integration and review

- [x] 2.1 Run the complete project test suite and configured pre-commit checks through project tooling; verify all pass without suppressions and confirm no lint/build script is omitted if none exists.
- [x] 2.2 Self-review the diff for duplication, named smells, overengineering, and redundant comments; resolve or justify findings and verify source changes remain within the confirmed inventory.
- [x] 2.3 Obtain code-reviewer and security conformance reviews against proposal, delta, design, and diff; resolve every blocker and record accepted/rejected dispositions for every warning before committing.
- [x] 2.4 Verify each delta scenario has a matching passing test and validate the completed change; confirm documented behavior and implemented role/block boundaries agree.

## Design-to-spec mapping

- D1 (strict role selection and accepted provenance limitation) → `Redact Secrets In Re-Derived Message History`: user-role, non-user-role, and provenance scenarios.
- D2 (default-off shared pipeline) → the same modified requirement; existing assembled-system scanning and tool-output requirements remain unchanged and receive negative regression coverage.
- D3 (per-block parsing and retained aggregation) → history boundary/mixed-block scenarios; existing annotation requirement remains unchanged.
- Chained/repeated scans and fail-open behavior → the new history scenarios; existing request-assembly coverage requirement remains unchanged.
- Existing helpers are the only components changed; no new component or public contract requires another capability. YAGNI, migration/rollback, resource-profile observations, and design process notes generate no additional spec requirement because they add no observable behavior.

## Verification record

- Implementation approved by the user on 2026-10-15; user subsequently requested getting the reviewed change to main.
- Baseline: `npm test`, 288 tests passed. Test-first reproduction: 10 intended fence-preservation failures, 57 passing conformance tests, before changing source. Negative/unchanged invariants already passed; no artificial failing tests were introduced for unchanged behavior.
- Green: `npm test`, 311 tests across 9 files passed. Corrected one test-only annotation separator expectation to match existing `+` formatting; annotation implementation was unchanged.
- `pre-commit run --all-files`: all eight configured hooks passed. No separate lint/build script exists; no configuration was added.
- Self-review: existing parser and traversal reused, only a default-off private policy added; no duplicated parser, new abstraction layer, unrelated refactor, or narration comment introduced. Shared test inputs exercise role and hook boundaries without copying cases. README-only wording is verified by diff review, not literal-copy tests.
- Review: code-reviewer approved and security passed, with no blockers or warnings. The optional extra provenance-shaped outside-secret test was not added because the mixed-user-role test already covers the same behavior. Accepted the archive-reference note: new spec comments point at the durable main-spec path rather than the temporary change directory. No behavior changed after review.
- Coverage: all ten delta scenario titles have matching tests (two pre-existing, eight new); request-specific cases run for each of the three hooks. Strict OpenSpec validation passed before approval and after implementation.

## Workflow follow-up

- After implementation approval, complete the tracked tasks and commit the reviewed fix and docs.
- Archive through OpenSpec so the delta updates the main spec, then commit archival separately.
- Push, verify the PR and clean task state, and remove the isolated worktree only after push and PR verification.
