# Spec Delta

## MODIFIED Requirements

### Requirement: Redact Secrets In Re-Derived Message History
The system SHALL scan text in re-derived message history for a provider request, replacing detected secrets except inside well-formed `noredact` fences in text blocks whose message role is exactly `user`. The exemption uses the existing user-message fence grammar independently per block, regardless of authorship or provenance. Non-text content remains unaffected.

#### Scenario: Redacts a secret in a message's text content
- **WHEN** a message in a re-derived history payload has text content
  containing a detectable secret outside an exempt fence
- **THEN** that content's secret is replaced with a redaction placeholder

#### Scenario: Non-text message content is left untouched
- **WHEN** a message in a re-derived history payload contains content that
  is not plain text (e.g. a tool call, a tool result, or reasoning content)
- **THEN** that content is left completely unmodified

#### Scenario: User-role fences survive each request-assembly stage
- **WHEN** a primary, auxiliary generation, or compaction request contains a user-role text block with a well-formed `noredact` fence containing a detectable secret
- **THEN** the entire fenced span, including its delimiters, remains byte-identical and no annotation is added solely for that exempt span

#### Scenario: User-role fences survive chained and repeated rescans
- **WHEN** the output of incoming-prompt processing containing a fenced secret and surrounding detectable text is passed through primary, auxiliary generation, and compaction request processing and then scanned again
- **THEN** the fenced span remains byte-identical at every stage, the surrounding secret is redacted, and no new annotation is added when a rescan finds nothing new
- **AND** a newly introduced secret outside the fence is redacted on a subsequent scan

#### Scenario: Mixed user-role blocks retain aggregate annotations
- **WHEN** multiple user-role text blocks contain detectable secrets outside valid fences and exempt secrets inside them, alongside non-text content
- **THEN** only the outside secrets are redacted and counted, exactly one request-stage annotation is appended to the last redacted block, and the exempt spans, non-text content, and other block fields are preserved

#### Scenario: Malformed user-role fences remain scanned
- **WHEN** a user-role block contains a detectable secret within an invalid opener, an unterminated fence, or a fence with a mismatched closing delimiter
- **THEN** the invalid fenced content receives ordinary secret scanning and the detectable secret is replaced

#### Scenario: Fences cannot span text blocks or messages
- **WHEN** a `noredact` opener is in one text block or message and its closing delimiter is in another
- **THEN** no cross-boundary exemption is established and detectable secrets in both blocks receive ordinary scanning

#### Scenario: Non-user roles receive no fence exemption
- **WHEN** a system-role, assistant-role, tool-role, unknown-role, or missing-role message contains a detectable secret inside a valid `noredact` fence
- **THEN** the secret is redacted at every supported request-assembly stage
- **AND** role matching is exact; differently cased or non-string roles receive no exemption

#### Scenario: User-role exemption does not require human-authorship metadata
- **WHEN** synthetic text, expanded file text, or a compaction summary is represented as user-role text containing a well-formed `noredact` fence
- **THEN** the fenced span is exempt on the same basis as any other user-role text, without requiring or inferring provenance metadata

#### Scenario: User-role rescan failures retain fail-open behavior
- **WHEN** scanning a non-exempt user-role text segment fails or times out
- **THEN** that segment remains unchanged, valid fenced spans remain unchanged, and the hook resolves without an annotation for the failed scan
