# Tasks

## 1. Red step

- [x] 1.1 Add failing tests in `test/entropy-rule.test.js` for each scenario of "Exempt Opencode Identifiers From Detection" (session, other prefixes, glued secret, wrong suffix length, unknown prefix); verify they fail on the current code

## 2. Implementation

- [x] 2.1 In `src/entropy-rule.js`, add an anchored `OPENCODE_ID_PATTERN` for the listed prefixes plus `_` plus 26 base-62 characters, and include it in `isAllowlistedRun`; verify the step 1.1 tests pass
- [x] 2.2 Verify the existing suite passes with `npm test`, including the existing allowlist fixtures

## Workflow follow-up

- Review with `code-reviewer`, then commit and push.
- Archive the change (`docs: archive openspec change exempt-opencode-ids-from-entropy`).
