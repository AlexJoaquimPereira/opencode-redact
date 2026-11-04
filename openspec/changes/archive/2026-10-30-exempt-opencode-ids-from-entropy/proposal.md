# Proposal

## Why

opencode session IDs (`ses_` plus a 26-character mixed-case base-62 suffix) are shown in tool output and are being redacted as high-entropy secrets (`***REDACTED:high-entropy***`). They are identifiers, not credentials, and the redaction hides them from the user and the agent.

## What Changes

- The high-entropy rule exempts opencode-generated identifiers whose whole candidate run matches an anchored shape: a known opencode ID prefix, `_`, then exactly 26 base-62 characters.
- Prefixes covered: `ses`, `msg`, `prt`, `per`, `psv`, `frm`, `wrk`, `evt`, `sh`, `cred`, `pty`, `con`.
- Partial matches (glued secret, wrong suffix length, unknown prefix) remain detected.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `high-entropy-secret-detection`: adds an allowlist exemption for opencode identifiers.

## Impact

- `src/entropy-rule.js`: new anchored pattern added to `isAllowlistedRun`.
- `test/entropy-rule.test.js` and related fixtures: coverage for the exemption.
- No change to the prescreen, password-shaped path, JWT/URL/path handling, or thresholds.
- Accepted residual risk: a real credential shaped as a listed prefix plus 26 base-62 characters (for example a short prefix such as `cred_` or `sh_`) is not reported. The prefix list is kept complete by decision, to match all opencode ID producers.
