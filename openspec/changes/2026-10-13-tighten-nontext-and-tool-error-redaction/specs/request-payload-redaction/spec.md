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
