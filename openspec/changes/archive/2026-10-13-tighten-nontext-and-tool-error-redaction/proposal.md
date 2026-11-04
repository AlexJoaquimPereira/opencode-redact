## Why

Tool failures and replayed tool arguments/results can carry secrets into
provider requests. Users need these paths covered without corrupting host
error objects, persisted history, or provider signature metadata. Structured
payloads also need bounded traversal and observable fail-open limits.

## What Changes

- Redact the tool-error payload in place on `execute.after`
  (`status === "error"`), preserving the `Tool.Error` Schema.Class identity.
- Scan text-bearing `ContentPart` variants in the assembled
  request: `tool-call.input`, `tool-result.result.value`
  (`json`/`text`/`error` and the text blocks of `content`), and
  `compaction` `.text` — while leaving `media` and `effort` parts untouched.
  `reasoning` parts remain exempt as provider-signed state.
- Register `ctx.session.hook("title", ...)` so the title request is covered.
- Use `Object.getOwnPropertyNames` (not `Object.keys`) in the in-place and
  clone walkers so non-enumerable own fields are scanned.
- Annotate a redaction that is carried only by a structured `output.output`.
- Scan `Tool.Result.metadata` in the V1 adapter too, without extending V2 traversal guarantees to V1.
- Honor `OPENCODE_CONFIG_DIR` when resolving the plugin's `redact.jsonc`.
- Correct the V2 install instructions and add a preset-rule pin so a
  dependency bump that adds a rule cannot silently bypass the prescreen.
- Bound structured traversal, warn on skipped branches without logging
  payloads, and isolate request-container failures.

## Scope Boundaries

Keep user-role fence exemptions, signature metadata and call ordering.
Session edits affect derived request payloads; tool errors retain host
identity. No new dependencies, settings, configurable logging, or
provider-specific redaction bypasses are included. Signed reasoning and
unscanned branches remain explicit confidentiality limitations.
