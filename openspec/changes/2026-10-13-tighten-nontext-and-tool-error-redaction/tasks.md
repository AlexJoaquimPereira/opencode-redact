## 1. Tool errors

- [x] Redact `event.error` in place on `execute.after` for `status === "error"`
- [x] Use `getOwnPropertyNames` so non-enumerable `message`/`stack` are scanned
- [x] Test with a non-enumerable `message` (Tool.Error shape)

## 2. Non-text message history

- [x] Deep-scan `tool-call.input` and `tool-result.result.value`
- [x] Scan `compaction` `.text`; leave `media`/`effort` untouched
- [x] Exempt provider-signed `reasoning` parts (post-review; keep text +
      `providerMetadata` intact — see "Post-review adjustments")
- [x] Scan only `type:"text"` parts for the model-facing annotation
- [x] Tests across all request-assembly hooks

## 3. Title request-assembly point

- [x] Register `ctx.session.hook("title", ...)`
- [x] Cover it in the shared hook-name test loop

## 4. Related gaps

- [x] Annotate a redaction carried only by a structured `output.output`
- [x] V1 adapter scans `Tool.Result.metadata` (parity with V2)
- [x] Honor `OPENCODE_CONFIG_DIR` in `resolveConfigPath`
- [x] Pin the recommend-preset rule set (prescreen dependency-bump tripwire)
- [x] Correct the README V2 install instructions
