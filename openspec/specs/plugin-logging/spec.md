# plugin-logging Specification

## Purpose

Optional, configurable, fail-open logging of plugin lifecycle and redaction
events, so an operator can observe what the plugin did without ever exposing a
secret value. This exists because the V2 plugin context has no logger
(`ctx.app` carries only `{name, version, channel}`) and `process.stderr` from a
managed opencode server is not captured in opencode's own log file — so
redaction events were effectively invisible in normal operation.

## Requirements

### Requirement: Configurable Level And Sink

The system SHALL read an optional `log` object from `redact.jsonc` supporting
`level` (`silent` | `error` | `warn` | `info` | `debug`), `sink` (`stderr` |
`file` | `none`), an optional `file` path, and an optional `maxBytes`. When a
value is absent or invalid the system SHALL fall back to that key's default
(level `warn`, sink `stderr`, file unset, `maxBytes` 1048576) and SHALL log a
warning naming only the key, without failing.

#### Scenario: Default level drops info and debug
- **WHEN** no `log` block is configured
- **THEN** `warn` and `error` records are emitted and `info`/`debug` records
  are dropped

#### Scenario: Silent disables all output
- **WHEN** `log.level` is `silent`
- **THEN** no record is emitted for any level

#### Scenario: Unknown or wrong-typed sub-key falls back with a warning
- **WHEN** `log` contains an invalid `level` or an unknown sub-key
- **THEN** that setting falls back to its default, a warning naming the key is
  logged, and every other validly-typed setting is still applied

### Requirement: File Sink Writes JSON Lines To An XDG Path

When `log.sink` is `file`, the system SHALL append one JSON object per record
(`ts`, `level`, `message`, and any structured fields) to the configured path,
defaulting to `<XDG state>/opencode/opencode-redact.log`, creating parent
directories as needed and using file mode `0600`. The system SHALL rotate the
file by renaming it to `<file>.1` once its size reaches `maxBytes`.

#### Scenario: A redaction record is written as JSON
- **WHEN** the file sink is active and a redaction occurs
- **THEN** a single JSON line is appended containing the timestamp, level,
  message, and the redaction's safe fields (source, count, rule ids)

#### Scenario: Oversized file is rotated
- **WHEN** the log file's size reaches `maxBytes`
- **THEN** it is renamed to `<file>.1` and a new file is started

### Requirement: Never Log Secret Or Configuration Values

A log record SHALL contain only non-sensitive metadata — timestamps, levels,
counts, detection rule ids, a source label, a tool name, and configuration key
names — and SHALL NOT contain a detected secret value, the text in which it
was found, a scanner-internal finding message, or any configuration value.

#### Scenario: A redaction record omits the matched text
- **WHEN** a redaction is logged
- **THEN** the record contains the count and rule ids, and neither the matched
  secret nor the surrounding text

### Requirement: Logging Is Fail-Open

The system SHALL never throw, reject, or otherwise break a hook or a turn
because of a logging failure, including a throwing or unwritable sink.

#### Scenario: A throwing sink does not propagate
- **WHEN** the log sink throws while writing a record
- **THEN** the error is swallowed and the caller continues normally
