## 1. Logger

- [x] `src/log.js`: levels, `stderr`/`file`/`none` sinks, `maxBytes` rotation
- [x] `normalizeLogConfig` with per-key fallback + warnings
- [x] Fail-open on sink errors

## 2. Configuration

- [x] Parse and validate the `log` block in `redact.jsonc`
- [x] Tests for valid/invalid `log`

## 3. Wiring

- [x] V2 adapter uses the configured logger; structured redaction fields
- [x] Default behavior unchanged (stderr, `warn`+)

## 4. Specs / docs

- [x] `plugin-logging` capability spec
- [x] Recognize `log` in `plugin-configuration`
- [x] Document `log` in the README

## 5. Test isolation

- [x] vitest setup pins XDG paths to a temp dir so a real `redact.jsonc`
      cannot affect tests
