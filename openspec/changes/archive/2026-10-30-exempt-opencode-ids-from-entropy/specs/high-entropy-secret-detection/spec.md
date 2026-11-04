# Spec Delta

## ADDED Requirements

### Requirement: Exempt Opencode Identifiers From Detection

The system SHALL NOT report as a high-entropy secret a candidate run that consists entirely of an opencode identifier: one of the known opencode ID prefixes (`ses`, `msg`, `prt`, `per`, `psv`, `frm`, `wrk`, `evt`, `sh`, `cred`, `pty`, `con`), an underscore, then exactly 26 base-62 characters (`0-9`, `A-Z`, `a-z`). The exemption applies to the whole run only.

#### Scenario: Exempts a session identifier

- **WHEN** tool output contains a standalone `ses_` followed by 26 mixed-case alphanumeric characters
- **THEN** the system does not report that identifier as a high-entropy finding

#### Scenario: Exempts other opencode identifier prefixes

- **WHEN** tool output contains a standalone `msg_`, `prt_`, or `per_` identifier with 26 base-62 characters
- **THEN** the system does not report that identifier as a high-entropy finding

#### Scenario: Still reports a secret glued to an identifier

- **WHEN** a candidate run is an opencode identifier with additional text appended or prepended
- **THEN** the system reports the run as a high-entropy finding

#### Scenario: Still reports an identifier with the wrong suffix length

- **WHEN** a candidate run has a known opencode prefix and a suffix of 25 or 27 base-62 characters
- **THEN** the system reports the run as a high-entropy finding

#### Scenario: Still reports an unknown prefix

- **WHEN** a candidate run has an unrecognised `<word>_` prefix followed by 26 base-62 characters and the entropy exceeds the threshold
- **THEN** the system reports the run as a high-entropy finding
