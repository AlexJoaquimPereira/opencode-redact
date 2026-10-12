## MODIFIED Requirements

### Requirement: Handle Non-Scannable Output Gracefully
The system SHALL leave tool output unmodified, without invoking the secret
scanner, when that output is empty, absent, or not a string — except that
when a structured (non-string) output value carries its own nested string
field duplicating the same text already exposed elsewhere in the tool's
result, the system SHALL scan and redact that nested string field too,
leaving every other field of the structured value unchanged. Independently
of the tool's output, every string value found anywhere within a tool
result's metadata SHALL be scanned and redacted, leaving every non-string
field, and every field that is itself free of a detectable secret,
unchanged. When a tool's output is delivered as discrete segments of
different kinds, the system SHALL scan only text-kind segments and SHALL
leave any non-text segment (e.g. a reference to a file's contents, rather
than the file's contents themselves) completely untouched. The system SHALL
scan a tool invocation's error payload when that invocation did not complete
successfully, replacing each detected secret so a failure's stack trace or
error body never reaches the LLM. The system SHALL bound the total volume of
text scanned within a single tool result's metadata, so that an unusually
large or deeply nested metadata value cannot make the scan itself unbounded.

#### Scenario: Output of an unsuccessful tool invocation IS scanned
- **WHEN** a tool invocation did not complete successfully (it errored) and
  its error payload contains a detectable secret
- **THEN** that secret is replaced with a redaction placeholder before the
  error reaches the LLM
