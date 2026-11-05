## MODIFIED Requirements

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
- **AND** an identifier matching `[A-Za-z_][A-Za-z0-9_]*` at an existing path-start boundary followed immediately by `=` permits those same path anchors at the beginning of its value
- **AND** the identifier and equals sign remain outside the exempt span and are scored normally
- **AND** embedded equals signs or internal slashes in otherwise unanchored credential values do not establish assignment-path exemptions

#### Scenario: Keeps explicit credential detection active inside exempt spans
- **WHEN** an exempt URL or filesystem path, including an identifier-assigned path, contains a credential recognized by an explicit secret-pattern rule
- **THEN** that rule still reports the credential

#### Scenario: Keeps JWT signature detection active inside exempt spans
- **WHEN** a URL or filesystem path, including an identifier-assigned path, contains a JWT-shaped token with a nonempty signature
- **THEN** the signature is still reported by the JWT detector
