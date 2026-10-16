# request-payload-redaction Specification

## Purpose
Scans the system prompt and message-history payload assembled for every
provider call — independent of what the tool-output and user-message
redaction paths already cover — so a secret embedded in system content
(skills, `AGENTS.md`, reference docs, MCP tool descriptions) or re-derived
message history never reaches a model provider.

## Requirements

### Requirement: Redact Secrets In The Assembled System Prompt
The system SHALL scan every text-bearing system prompt segment assembled for
a provider request and SHALL replace each detected secret substring with a
redaction placeholder before that request is sent, leaving the rest of each
segment unchanged.

#### Scenario: Redacts a known-detectable secret in a system prompt segment
- **WHEN** a system prompt segment assembled for a provider request contains
  a substring matching a known secret pattern
- **THEN** that substring is replaced with a redaction placeholder and the
  surrounding text is preserved unchanged

#### Scenario: Leaves a clean system prompt segment unchanged
- **WHEN** a system prompt segment contains no detectable secret
- **THEN** the segment is left exactly as assembled, with no placeholder
  inserted

### Requirement: Redact Secrets In Re-Derived Message History
The system SHALL scan the text-bearing content of every message in a
re-derived message-history payload assembled for a provider request and
SHALL replace each detected secret substring with a redaction placeholder.
This covers every `ContentPart` variant that carries model-bound text —
`text` and `compaction` parts' `.text`, a `tool-call` part's `input`, and a
`tool-result` part's `result.value` (its `json`/`text`/`error` variants and
the text blocks of its `content` variant). Within a `text` block whose
message role is exactly `user`, a well-formed `noredact` fence is exempt,
using the existing user-message fence grammar independently per block,
regardless of authorship or provenance. A `reasoning` part SHALL be left
completely unmodified — including its text and `providerMetadata` — because
its metadata certifies the text ("provider-signed reasoning") and provider
SDKs (e.g. Anthropic, AWS Bedrock) reject requests whose thinking blocks
were modified after generation; scanning it is deferred to a follow-up with
a provider-compatible confidentiality policy. Media parts
(binary/base64/url/ref) and `effort` parts SHALL be left completely
unmodified.

#### Scenario: Redacts a secret in a message's text content
- **WHEN** a message in a re-derived history payload has text content
  containing a detectable secret outside an exempt fence
- **THEN** that content's secret is replaced with a redaction placeholder

#### Scenario: Redacts a secret in a tool-call input or tool-result value
- **WHEN** a message in a re-derived history payload contains a `tool-call`
  input or a `tool-result` value with a detectable secret
- **THEN** that secret is replaced with a redaction placeholder

#### Scenario: Media content is left untouched
- **WHEN** a message in a re-derived history payload contains a `media` part
- **THEN** that part is left completely unmodified

#### Scenario: Signed reasoning is left untouched
- **WHEN** a message in a re-derived history payload contains a `reasoning`
  part that carries `providerMetadata` proof-of-generation
- **THEN** the part is left completely unmodified — its text keeps the
  detected secret and its `providerMetadata` is unchanged — and no
  annotation is added

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

### Requirement: Cover Every Request-Assembly Point Independently
The system SHALL apply system-prompt and message-history redaction whenever
a request payload is assembled or re-derived for a provider call — including
the primary agent loop's request, a one-shot auxiliary generation request
issued by any installed component, and a conversation-compaction request —
so that no such assembly point can bypass this redaction.

#### Scenario: An auxiliary one-shot generation request is redacted
- **WHEN** a one-shot generation request is issued with system or message
  content containing a detectable secret, independent of the primary agent
  loop
- **THEN** that secret is redacted before the request is sent

#### Scenario: A compaction request is redacted
- **WHEN** a conversation-compaction request re-derives system or message
  content containing a detectable secret
- **THEN** that secret is redacted before the request is sent

### Requirement: Annotate On Redaction, Once Per Assembled Container
The system SHALL append a note when a redaction occurred in an assembled
system prompt or in a message's content, instructing that a redaction
placeholder must never be written back to a file, command, or message, and
SHALL append exactly one such note per container (the system prompt as a
whole; each message independently) even when multiple segments within that
same container were redacted.

#### Scenario: One annotation for multiple redactions in the system prompt
- **WHEN** redactions occur in more than one system prompt segment for the
  same request
- **THEN** exactly one annotation is appended, reporting the combined count
  and rule identifiers across every affected segment

#### Scenario: No annotation when no redaction occurred
- **WHEN** no secret is found in the assembled system prompt or a message's
  content
- **THEN** no annotation is appended
