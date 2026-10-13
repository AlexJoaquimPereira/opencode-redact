## Why

The V2 plugin context exposes no logger (`ctx.app` is only
`{name, version, channel}`), and `process.stderr` from a managed opencode
server is not captured in opencode's own log file. As a result, redaction
events were effectively invisible in normal operation — an operator could not
tell whether the plugin was running or what it redacted.

## What Changes

- Add `src/log.js`: a level-filtered, fail-open logger with `stderr`
  (default, back-compatible), `file` (JSONL under the XDG state directory,
  0600, size-capped rotation), and `none` sinks.
- Extend `redact.jsonc` with a `log` object (`level`, `sink`, `file`,
  `maxBytes`), validated per-key with the existing failure ladder.
- Wire the V2 adapter to the configured logger; emit lifecycle and redaction
  events with safe structured fields (source, count, rule ids) and never the
  matched secret or its surrounding text.
- Add the `plugin-logging` capability spec; recognize `log` as a known key in
  `plugin-configuration`.

## Out Of Scope

- A fingerprint of the matched secret (correlation without exposure) and
  storage-backed aggregate counters via `ctx.storage` — deferred.
- Routing V1 logging through the configured sink; V1 continues to use the
  host's structured `client.app.log`.
