## REMOVED Requirements

### Requirement: Treat URL Path Separators As Candidate-Run Boundaries
**Reason**: Segment scoring still redacts ordinary URL and filesystem-path content.
**Migration**: Replace separator splitting and path-discard restrictions with the complete-span exemptions below.

## ADDED Requirements

### Requirement: Exempt URL And Filesystem Path Spans From Entropy Scoring
The system SHALL exclude complete URL and anchored filesystem-path spans from generic and short-password entropy scoring, without disabling explicit secret-pattern rules or unconditional JWT-signature detection.

#### Scenario: Preserves complete URLs regardless of segment entropy
- **WHEN** a scheme-shaped `scheme://` URL contains high-entropy host, userinfo, path, query, or fragment text
- **THEN** neither entropy-scoring pass reports that URL content
- **AND** spans terminate at whitespace, quotes, backticks, or round/square/curly/angle brackets; commas and semicolons remain URL content

#### Scenario: Preserves complete Linux and Windows filesystem paths
- **WHEN** a boundary-anchored path begins with `/`, `./`, `../`, `~/`, a Windows drive plus either separator, a UNC prefix, or a backslash relative anchor
- **THEN** neither entropy-scoring pass reports any path segment, including single-segment paths and paths containing `+` or `=`
- **AND** path spans use the same terminators as URL spans

#### Scenario: Keeps explicit credential detection active inside exempt spans
- **WHEN** an exempt URL or filesystem path contains a credential recognized by an explicit secret-pattern rule
- **THEN** that rule still reports the credential

#### Scenario: Keeps JWT signature detection active inside exempt spans
- **WHEN** a URL or filesystem path contains a JWT-shaped token with a nonempty signature
- **THEN** the signature is still reported by the JWT detector

### Requirement: Exempt Complete Numeric Values From Entropy Scoring
The system SHALL exclude complete signed or unsigned decimal numeric values from entropy scoring, including integer and decimal mantissas and optional signed scientific exponents, when standalone, delimited, or assigned after an identifier and `=` or `:`.

#### Scenario: Preserves integers decimals and scientific notation
- **WHEN** a message contains complete numeric values, including long digit sequences, leading/trailing decimal points, signs, or scientific exponents
- **THEN** no entropy finding covers those values
- **AND** assignment labels remain outside the numeric exemption

#### Scenario: Does not exempt numeric fragments inside credentials
- **WHEN** a detectable nonnumeric credential contains numeric-looking prefixes, suffixes, or decimal/scientific fragments
- **THEN** numeric recognition does not suppress its entropy findings

### Requirement: Bound Entropy Exemptions To Recognized Spans
The system SHALL retain entropy detection outside recognized exemption intervals, including outside portions of candidates crossing an exemption boundary, without interpreting unanchored slash-containing credentials as filesystem paths.

#### Scenario: Detects secrets adjacent to exempt spans
- **WHEN** generic or short-password secrets occur outside exempt spans separated by the defined terminators
- **THEN** their original source ranges are reported while exempt content remains unreported

#### Scenario: Detects outside fragments of candidates crossing exemption boundaries
- **WHEN** an entropy candidate crosses into a recognized URL or filesystem-path span
- **THEN** its outside fragment is independently scored at its original source offsets

#### Scenario: Leaves unanchored slash-containing credentials detectable
- **WHEN** a detectable slash-containing credential has no boundary-anchored path or scheme-shaped URL
- **THEN** it remains scored normally
