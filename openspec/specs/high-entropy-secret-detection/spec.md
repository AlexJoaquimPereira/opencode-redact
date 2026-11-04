# high-entropy-secret-detection Specification

## Purpose
Detects secret-shaped substrings that no vendor-pattern rule can catch —
bespoke or opaque credentials with no known prefix or fixed format — using
Shannon-entropy scoring, sharing the same scan/merge/splice/annotate
pipeline that `tool-output-redaction` and `user-message-redaction` already
specify. This capability adds only the detection-specific behavior; the
fail-open-on-scanner-error, never-log-matched-values, and
annotate-on-redaction guarantees are already specified by those two
capabilities and apply here unchanged.

## Requirements

### Requirement: Detect High-Entropy Secret-Shaped Substrings
The system SHALL flag a substring as a candidate high-entropy secret when
its Shannon entropy strictly exceeds a threshold defined by its character
set: 4.5 bits per character for a substring drawn from the base64 alphabet,
or 3.0 bits per character for a substring drawn from the hexadecimal
alphabet, and SHALL NOT evaluate a substring shorter than the minimum
length for which that threshold is mathematically achievable.

#### Scenario: Flags a base64-shaped substring exceeding the base64 threshold
- **WHEN** a message contains a substring drawn from the base64 alphabet
  whose measured Shannon entropy is strictly greater than 4.5 bits/char
- **THEN** that substring is reported as a candidate high-entropy secret

#### Scenario: Flags a hex-shaped substring exceeding the hex threshold
- **WHEN** a message contains a substring drawn only from hexadecimal
  characters whose measured Shannon entropy is strictly greater than 3.0
  bits/char
- **THEN** that substring is reported as a candidate high-entropy secret

#### Scenario: Does not flag a substring at or below its threshold
- **WHEN** a message contains a base64-shaped or hex-shaped substring whose
  measured entropy is less than or equal to the threshold for its
  character set
- **THEN** that substring is not reported

#### Scenario: Does not evaluate a substring below the minimum length floor
- **WHEN** a candidate substring is shorter than the minimum length at
  which its character set's threshold is mathematically reachable
- **THEN** that substring is never reported, regardless of its measured
  entropy

### Requirement: Exempt Case-Uniform Git Object IDs And Hash Digests
The system SHALL NOT report a hexadecimal substring as a high-entropy
secret when it is entirely lowercase or entirely uppercase and its length
is 7 through 12 characters (an abbreviated git object id) or exactly 32,
40, 64, or 128 characters (a common hash-digest output length), and SHALL
evaluate a hexadecimal substring of the same length normally when its case
is mixed.

#### Scenario: Exempts a lowercase abbreviated git commit id
- **WHEN** a message contains a lowercase hexadecimal substring 7 to 12
  characters long
- **THEN** that substring is not reported, even if its measured entropy
  exceeds the hex threshold

#### Scenario: Exempts an uppercase 40-character hash digest
- **WHEN** a message contains an uppercase hexadecimal substring exactly 40
  characters long
- **THEN** that substring is not reported

#### Scenario: Does not exempt a mixed-case hexadecimal substring of the same length
- **WHEN** a message contains a hexadecimal substring of a length that
  would otherwise be exempt, but its characters mix uppercase and
  lowercase
- **THEN** that substring is evaluated against the hex threshold normally
  and is reported if it exceeds it

### Requirement: Exempt UUIDs From Detection
The system SHALL NOT report a substring matching the canonical
8-4-4-4-12 hyphenated hexadecimal UUID shape as a high-entropy secret,
regardless of letter case.

#### Scenario: Exempts a canonically-formatted UUID
- **WHEN** a message contains a substring matching the 8-4-4-4-12
  hyphenated hexadecimal UUID shape
- **THEN** that substring is not reported, regardless of its measured
  entropy or letter case

### Requirement: Exempt Subresource Integrity Hashes From Detection
The system SHALL NOT report a substring matching the Subresource Integrity
format (a `sha1`, `sha256`, `sha384`, or `sha512` algorithm prefix followed
by a `-` and a base64-encoded digest) as a high-entropy secret.

#### Scenario: Exempts a Subresource Integrity hash
- **WHEN** a message contains a substring of the form
  `sha256-<base64-digest>` (or the `sha1`/`sha384`/`sha512` equivalent)
- **THEN** that substring is not reported, even though its digest portion
  exceeds the base64 threshold

### Requirement: Detect A JWT Via Its Signature Segment
The system SHALL treat a JWT-shaped span (three period-separated
base64url segments, the first beginning with the `eyJ` header prefix) as
exempt from generic entropy scoring on its header and payload segments,
and SHALL report its signature segment as a finding unconditionally
(without regard to the signature's own measured entropy) whenever that
segment is non-empty. Because the redaction pipeline's existing
token-boundary expansion widens every finding to the nearest whitespace
and a JWT contains no internal whitespace, the observable effect in this
capability's current version is that the entire token is replaced by a
single redaction placeholder — the header and payload claims are not
separately preserved.

#### Scenario: A signed JWT is fully redacted as a single placeholder
- **WHEN** a message contains a JWT-shaped span with a non-empty signature
  segment
- **THEN** the entire span, from the start of the header segment through
  the end of the signature segment, is replaced by a single redaction
  placeholder

#### Scenario: An unsigned JWT (empty signature) is not flagged
- **WHEN** a message contains a JWT-shaped span whose signature segment is
  empty (an unsigned, `alg: none`-style token)
- **THEN** no finding is reported for that span, and its header and
  payload segments are not independently evaluated against the generic
  entropy thresholds either

### Requirement: High-Entropy Detection Is Exempt From The Anchor-Based Prescreen
The system SHALL evaluate every scanned message for high-entropy
substrings regardless of whether the anchor-based prescreen (see
`tool-output-redaction`'s Prescreen requirement) would otherwise skip the
full scan, because a high-entropy secret has no literal anchor for that
prescreen to detect.

#### Scenario: High-entropy detection runs even when no anchor is present
- **WHEN** a message contains no substring any anchor-based detection rule
  requires, but does contain a high-entropy substring exceeding its
  charset's threshold and not covered by an allowlist exemption
- **THEN** that substring is still reported

### Requirement: Detect Short Password-Shaped High-Entropy Substrings
The system SHALL flag a substring drawn from an expanded password-shaped
character set (upper- and lowercase letters, digits, and the punctuation
characters `! # $ % ^ + - _ ~ @`) as a candidate high-entropy secret when
its length is between 14 and 22 characters inclusive, it contains at
least one lowercase letter and at least one uppercase letter, it contains
no run of four or more consecutive characters from the same character
class (lowercase, uppercase, digit, or symbol), and its Shannon entropy
strictly exceeds 3.75 bits per character, and SHALL NOT flag such a
substring when any of those conditions is not met.

#### Scenario: Flags a password-shaped substring meeting every condition
- **WHEN** a message contains a 14-to-22-character substring, drawn from
  the password-shaped character set, containing both a lowercase and an
  uppercase letter, with no run of four or more same-class characters,
  whose measured Shannon entropy is strictly greater than 3.75 bits/char
- **THEN** that substring is reported as a candidate high-entropy secret

#### Scenario: Does not flag a substring below the 14-character floor
- **WHEN** a password-shaped candidate substring is 13 characters or
  fewer
- **THEN** that substring is never reported by this path, regardless of
  its measured entropy or character composition

#### Scenario: Does not flag a substring missing a required letter case
- **WHEN** a password-shaped candidate substring contains only lowercase
  letters (or only uppercase letters), even if it otherwise meets the
  length and entropy conditions
- **THEN** that substring is not reported

#### Scenario: Does not flag a substring with a same-class character run of four or more
- **WHEN** a password-shaped candidate substring contains a run of four
  or more consecutive characters from the same character class (for
  example, four consecutive lowercase letters), even if it otherwise
  meets the length, case-mix, and entropy conditions
- **THEN** that substring is not reported

#### Scenario: Does not flag a substring at or below the entropy threshold
- **WHEN** a password-shaped candidate substring's measured Shannon
  entropy is less than or equal to 3.75 bits/char
- **THEN** that substring is not reported, even if it meets every other
  condition

#### Scenario: Symbols are optional, not required
- **WHEN** a password-shaped candidate substring contains only letters
  and digits (no punctuation), but otherwise meets every condition
- **THEN** that substring is still reported

### Requirement: Exempt Content Already Covered By An Existing Detection Path From The Short Password Path
The system SHALL NOT evaluate a password-shaped candidate substring
against the short password path when that substring falls within a
JWT-shaped span (see "Detect A JWT Via Its Signature Segment") or within
an existing-path allowlisted run (see the case-uniform git-object-id/
hash-digest, UUID, and Subresource Integrity exemptions), so the short
password path cannot reintroduce a false positive an existing path's
exemption already rules out, nor double-report content the existing JWT
handling already governs.

#### Scenario: Does not independently report a fragment of an allowlisted Subresource Integrity hash
- **WHEN** a message contains a Subresource Integrity hash whose digest
  portion contains a substring that would otherwise meet the short
  password path's length, case-mix, run-cap, and entropy conditions
- **THEN** that substring is not reported by the short password path

#### Scenario: Does not independently report a fragment of a JWT header or payload segment
- **WHEN** a message contains a JWT-shaped span whose header or payload
  segment contains a substring that would otherwise meet the short
  password path's length, case-mix, run-cap, and entropy conditions
- **THEN** that substring is not reported by the short password path

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
