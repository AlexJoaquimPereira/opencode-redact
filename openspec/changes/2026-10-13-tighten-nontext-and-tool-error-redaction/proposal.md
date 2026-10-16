## Why

An audit of the plugin's completeness guarantee ("no secret reaches the
model") found two request-bound paths that were never scanned:

1. **Failed tool calls.** `execute.after` returned early for
   `status !== "completed"`, so a secret in a tool error's stack trace, error
   body, or connection string reached the model unredacted.
2. **Non-text message history.** The `context`/`generate`/`compaction` hooks
   scanned only `type:"text"` blocks, so a secret in a `tool-call` input or a
   `tool-result` value (including its `error` variant) reached the provider
   unredacted. The `title` request-assembly hook was also never registered,
   leaving the auxiliary title-generation request (which carries `system[]` +
   `messages[]`) uncovered.

Two non-enumerable-field bugs compounded the first gap: `Tool.Error.message`
and `.stack` are non-enumerable own properties, so an `Object.keys` walk
missed them even when it ran.

## What Changes

- Redact the tool-error payload in place on `execute.after`
  (`status === "error"`), preserving the `Tool.Error` Schema.Class identity.
- Scan every other text-bearing `ContentPart` variant in the assembled
  request — `tool-call.input`, `tool-result.result.value`
  (`json`/`text`/`error` and the text blocks of `content`), and
  `compaction` `.text` — while leaving `media` and `effort` parts untouched.
  `reasoning` parts are exempt as provider-signed state (see "Post-review
  adjustments").
- Register `ctx.session.hook("title", ...)` so the title request is covered.
- Use `Object.getOwnPropertyNames` (not `Object.keys`) in the in-place and
  clone walkers so non-enumerable own fields are scanned.
- Annotate a redaction that is carried only by a structured `output.output`.
- Scan `Tool.Result.metadata` in the V1 adapter too (V1/V2 parity).
- Honor `OPENCODE_CONFIG_DIR` when resolving the plugin's `redact.jsonc`.
- Correct the V2 install instructions and add a preset-rule pin so a
  dependency bump that adds a rule cannot silently bypass the prescreen.

## Post-review adjustments (maintainer comments)

Two maintainer review points adjusted the plan above without changing its
intent — **no secret reaches the model unprotected**:

- **Signed reasoning is exempt.** An earlier revision scanned `reasoning`
  `.text`; a reason part's `providerMetadata` certifies its text
  (Anthropic signature, Gemini thought signature, OpenAI encrypted
  content) and Anthropic/AWS Bedrock reject requests whose thinking blocks
  are modified after generation — so redacting the text while keeping the
  signature (edits), dropping the metadata (traceability loss), or passing
  the secret through are all invalid. Redaction of signed reasoning is
  deferred to a follow-up change with a provider-compatible policy and a
  tool-use/replay regression test (see README "Known limitations").
- **Session-hook request-bound mutation is copy-on-write, in a derived
  payload.** The hook handler replaces array slots only (verified by
  deep-frozen-part, identity, and untouched-original tests). The host
  derives the hook-bound `system`/`messages` fresh per provider call and
  uses the hook result only for the outgoing request — the persisted
  session record is not reached (full trace with v2.0.26 file:line
  references in `docs/v2-compat-audit.md`, "Update — 2026-10-14").
