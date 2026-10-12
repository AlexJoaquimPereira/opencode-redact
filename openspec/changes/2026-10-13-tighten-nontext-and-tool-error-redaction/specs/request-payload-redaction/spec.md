## MODIFIED Requirements

### Requirement: Redact Secrets In Re-Derived Message History
The system SHALL scan the text-bearing content of every message in a
re-derived message-history payload assembled for a provider request and
SHALL replace each detected secret substring with a redaction placeholder.
This covers every `ContentPart` variant that carries model-bound text —
`text`, `reasoning`, and `compaction` parts' `.text`, a `tool-call` part's
`input`, and a `tool-result` part's `result.value` (its `json`/`text`/`error`
variants and the text blocks of its `content` variant). Media parts
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
