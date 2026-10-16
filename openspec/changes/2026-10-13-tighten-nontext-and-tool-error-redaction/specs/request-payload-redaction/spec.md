## MODIFIED Requirements

### Requirement: Redact Secrets In Re-Derived Message History
The system SHALL scan the text-bearing content of every message in a
re-derived message-history payload assembled for a provider request and
SHALL replace each detected secret substring with a redaction placeholder.
This covers every `ContentPart` variant that carries model-bound text —
`text` and `compaction` parts' `.text`, a `tool-call` part's `input`, and a
`tool-result` part's `result.value` (its `json`/`text`/`error` variants and
the text blocks of its `content` variant). A `reasoning` part SHALL be left
completely unmodified — including its text and `providerMetadata` — because
its metadata certifies the text ("provider-signed reasoning") and provider
SDKs (e.g. Anthropic, AWS Bedrock) reject requests whose thinking blocks
were modified after generation; scanning it is deferred to a follow-up with
a provider-compatible confidentiality policy. Media parts
(binary/base64/url/ref) and `effort` parts SHALL be left completely
unmodified.

#### Scenario: Redacts a secret in a message's text content
- **WHEN** a message in a re-derived history payload has text content
  containing a detectable secret
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

### Requirement: Annotate On Redaction, Once Per Assembled Container
The system SHALL append a note when a redaction occurred in an assembled
system prompt or in a message's content, instructing that a redaction
placeholder must never be written back to a file, command, or message, and
SHALL append exactly one such note per container (the system prompt as a
whole; each message independently) even when multiple segments within that
same container were redacted. The note SHALL be appended to the last
redacted part in the container that carries model-facing text (a string
`.text`); when a container's redactions all occur in parts with no `.text`
(a `tool-call` part's `input`, a `tool-result` part's `value`), no note can
be appended because no text-bearing part exists to carry it — the redaction
SHALL still be counted and reported.

#### Scenario: One annotation for multiple redactions in the system prompt
- **WHEN** redactions occur in more than one system prompt segment for the
  same request
- **THEN** exactly one annotation is appended, reporting the combined count
  and rule identifiers across every affected segment

#### Scenario: No annotation when no redaction occurred
- **WHEN** no secret is found in the assembled system prompt or a message's
  content
- **THEN** no annotation is appended

#### Scenario: No text-bearing part to carry the annotation
- **WHEN** a message's only redactions are in `tool-call` inputs or
  `tool-result` values, so no redacted part carries a `.text`
- **THEN** the redaction is counted and reported, and no annotation is
  appended because no text-bearing part exists to carry it

### Requirement: Cover Every Request-Assembly Point Independently
The system SHALL apply system-prompt and message-history redaction whenever
a request payload is assembled or re-derived for a provider call — including
the primary agent loop's request, a one-shot auxiliary generation request
issued by any installed component, a conversation-compaction request, and
the auxiliary title-generation request — so that no such assembly point can
bypass this redaction.

#### Scenario: An auxiliary one-shot generation request is redacted
- **WHEN** a one-shot generation request is issued with system or message
  content containing a detectable secret, independent of the primary agent
  loop
- **THEN** that secret is redacted before the request is sent

#### Scenario: A compaction request is redacted
- **WHEN** a conversation-compaction request re-derives system or message
  content containing a detectable secret
- **THEN** that secret is redacted before the request is sent

#### Scenario: A title-generation request is redacted
- **WHEN** a title-generation request carries system or message content
  containing a detectable secret
- **THEN** that secret is redacted before the request is sent
