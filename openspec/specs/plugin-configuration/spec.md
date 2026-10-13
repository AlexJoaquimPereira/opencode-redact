# plugin-configuration Specification

## Purpose
Loads an optional plugin settings file so a user can disable a specific
detection capability (currently only high-entropy detection) without
losing any other rule, while failing open on any load or parse problem so
a broken or unexpected configuration file never blocks the plugin from
starting or silently disables more than the user asked for.

## Requirements

### Requirement: Load Optional Configuration From The Host Application's Config Directory
The system SHALL look for a `redact.jsonc` file in the host application's
own configuration directory at plugin startup, and SHALL apply
all-default configuration when that file does not exist, without logging
an error or warning.

#### Scenario: Missing configuration file uses defaults silently
- **WHEN** no `redact.jsonc` file exists in the host application's
  configuration directory
- **THEN** the plugin starts with every setting at its default value and
  no log entry is produced about the missing file

### Requirement: Fail Open On A Malformed Configuration File
The system SHALL fall back to all-default configuration and SHALL log a
warning, rather than fail to start, when `redact.jsonc` exists but cannot
be parsed as valid JSONC or does not contain a JSON object at its root.

#### Scenario: Invalid JSONC syntax falls back to defaults
- **WHEN** `redact.jsonc` exists but contains content that is not valid
  JSONC
- **THEN** the plugin starts with every setting at its default value and a
  warning is logged

#### Scenario: Non-object root falls back to defaults
- **WHEN** `redact.jsonc` parses successfully but its root value is not a
  JSON object (for example, an array or a string)
- **THEN** the plugin starts with every setting at its default value and a
  warning is logged

### Requirement: Fail Open Per-Key On A Wrong-Typed Known Setting
The system SHALL apply a known setting's default value and SHALL log a
warning naming that key, rather than fail to start or discard the rest of
the file, when that key is present in `redact.jsonc` with a value of the
wrong type.

#### Scenario: Wrong-typed known key falls back to its own default only
- **WHEN** `redact.jsonc` contains the `disableHighEntropy` key with a
  non-boolean value
- **THEN** `disableHighEntropy` is applied at its default value, a warning
  naming that key is logged, and any other validly-typed key elsewhere in
  the same file is still applied as configured

### Requirement: Warn On Unknown Configuration Keys Without Failing
The system SHALL log a warning naming any key present in `redact.jsonc`
that this capability does not define, and SHALL continue applying every
recognized key normally. The recognized keys are the detection setting
`disableHighEntropy` (see "Disable High-Entropy Detection Via Configuration")
and the logging settings under `log` (see the `plugin-logging` capability);
`log` and its sub-keys are recognized, not unknown.

#### Scenario: Unknown key is warned about but does not block valid keys
- **WHEN** `redact.jsonc` contains a key this capability does not define,
  alongside a validly-typed known key
- **THEN** a warning naming the unknown key is logged and the known key is
  still applied as configured

### Requirement: Never Log Configuration File Values
The system SHALL NOT include the value of any configuration key — known,
unknown, correctly typed, or not — in any log entry produced while loading
or validating `redact.jsonc`; only key names, not their values, may appear.

#### Scenario: A log entry about a configuration problem omits the value
- **WHEN** a warning or error is logged in the course of loading
  `redact.jsonc`
- **THEN** that log entry contains no configuration value from the file,
  only key names

### Requirement: Disable High-Entropy Detection Via Configuration
The system SHALL omit high-entropy detection from every scan when
`redact.jsonc` sets `disableHighEntropy` to `true`, and SHALL include it,
per `high-entropy-secret-detection`'s requirements, whenever that key is
absent, `false`, or the file itself is absent or malformed.

#### Scenario: Explicit true disables high-entropy detection
- **WHEN** `redact.jsonc` sets `disableHighEntropy` to `true`
- **THEN** no high-entropy finding is ever reported for any subsequently
  scanned message, while every other detection rule continues to apply

#### Scenario: Absent, false, or unusable configuration leaves high-entropy detection enabled
- **WHEN** `redact.jsonc` is absent, malformed, or does not set
  `disableHighEntropy` to `true`
- **THEN** high-entropy detection is enabled
