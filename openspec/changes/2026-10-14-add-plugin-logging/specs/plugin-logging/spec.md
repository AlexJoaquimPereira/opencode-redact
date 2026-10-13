## ADDED Requirements

### Requirement: Configurable Level And Sink

The system SHALL read an optional `log` object from `redact.jsonc` supporting
`level` (`silent` | `error` | `warn` | `info` | `debug`), `sink` (`stderr` |
`file` | `none`), an optional `file` path, and an optional `maxBytes`. When a
value is absent or invalid the system SHALL fall back to that key's default
(level `warn`, sink `stderr`, file unset, `maxBytes` 1048576) and SHALL log a
warning naming only the key, without failing.

### Requirement: File Sink Writes JSON Lines To An XDG Path

When `log.sink` is `file`, the system SHALL append one JSON object per record
(`ts`, `level`, `message`, and any structured fields) to the configured path,
defaulting to `<XDG state>/opencode/opencode-redact.log`, creating parent
directories as needed and using file mode `0600`. The system SHALL rotate the
file by renaming it to `<file>.1` once its size reaches `maxBytes`.

### Requirement: Never Log Secret Or Configuration Values

A log record SHALL contain only non-sensitive metadata — timestamps, levels,
counts, detection rule ids, a source label, a tool name, and configuration key
names — and SHALL NOT contain a detected secret value, the text in which it
was found, a scanner-internal finding message, or any configuration value.

### Requirement: Logging Is Fail-Open

The system SHALL never throw, reject, or otherwise break a hook or a turn
because of a logging failure, including a throwing or unwritable sink.
