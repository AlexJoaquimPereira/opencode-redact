# tool-output-redaction Specification

## Purpose
Scans the text returned by every successful opencode tool call for secrets and
redacts them in place before that output is appended to the LLM's context, so
credentials accidentally surfaced by a tool never reach the conversation.

## Requirements

### Requirement: Redact Detected Secrets In Tool Output
The system SHALL replace each detected secret substring in a tool's output
with a redaction placeholder before the output reaches the LLM, leaving the
rest of the output unchanged. When a tool's output is delivered as multiple
discrete text segments rather than a single string, the system SHALL apply
this same redaction to each text segment independently.

#### Scenario: Redacts a known-detectable secret pattern
- **WHEN** a tool's output contains a substring matching a known secret
  pattern (e.g. an AWS-style access key)
- **THEN** that substring is replaced with a redaction placeholder and the
  surrounding text is preserved unchanged

#### Scenario: Leaves clean output unchanged
- **WHEN** a tool's output contains no detectable secret
- **THEN** the output is returned exactly as produced by the tool, with no
  placeholder inserted

#### Scenario: Redacts multiple distinct findings in one output
- **WHEN** a tool's output contains two or more separate, non-overlapping
  secret findings
- **THEN** every finding is replaced with its own redaction placeholder

#### Scenario: Redacts a secret in one segment of a multi-segment output
- **WHEN** a tool's output is delivered as multiple discrete text segments
  and a detectable secret appears in one of those segments
- **THEN** that segment's secret is replaced with a redaction placeholder,
  and every other segment is left byte-identical to its original content

### Requirement: Merge Overlapping Findings Before Redaction
The system SHALL merge overlapping or directly adjacent secret findings into
a single redaction placeholder rather than producing corrupted, duplicated,
or nested placeholder text.

#### Scenario: Merges two overlapping findings into one placeholder
- **WHEN** two separate secret findings in the same output have overlapping
  character ranges
- **THEN** the output contains exactly one redaction placeholder covering
  the full combined range, not two overlapping or nested placeholders

#### Scenario: Merges two findings adjacent within the same token
- **WHEN** two separate secret findings sit back-to-back with no whitespace
  between them
- **THEN** the output contains exactly one redaction placeholder covering
  both, not two placeholders separated by nothing

### Requirement: Expand Redaction To Token Boundaries
The system SHALL expand each redaction range to the nearest surrounding
whitespace boundary or structural delimiter character (`"`, `'`, `` ` ``,
`,`, `{`, `}`, `[`, `]`), whichever is nearer, so that a finding whose
reported range only partially covers its secret does not leave any part of
that secret in the output, while not expanding past a structural delimiter
that cannot form part of any detectable secret shape.

#### Scenario: Fully redacts a secret when the finding's range is partial
- **GIVEN** a finding whose reported range covers only part of the actual
  secret token (e.g. the label plus part of the value, not the whole value)
- **WHEN** redaction is applied
- **THEN** the entire secret token, up to the surrounding whitespace, is
  replaced by the placeholder, with no fragment of the secret remaining in
  the output

#### Scenario: Stops expansion at a structural delimiter in dense JSON
- **GIVEN** a finding inside a compact, single-line JSON value with no
  surrounding whitespace (e.g. a minified JSON array's string field)
- **WHEN** redaction is applied
- **THEN** the redaction placeholder replaces only the enclosing JSON value
  — up to its surrounding quote, comma, or bracket character — and does not
  consume any sibling field, array element, or the rest of the JSON document

### Requirement: Fail Open On Scanner Error Or Timeout
The system SHALL return the original tool output unmodified when the secret
scanner throws an error or exceeds its execution timeout, rather than
blocking the tool call or corrupting its result.

#### Scenario: Returns original text when the scanner throws
- **WHEN** the secret scanner raises an error while scanning a tool's output
- **THEN** the tool's output is returned to the caller exactly as produced,
  unmodified

#### Scenario: Returns original text when the scanner times out
- **WHEN** the secret scanner does not complete within its configured
  timeout
- **THEN** the tool's output is returned to the caller exactly as produced,
  unmodified

### Requirement: Fail Loud On Startup Configuration Failure
The system SHALL prevent the plugin from loading silently and SHALL log an
error when the secret-scanner rule configuration fails to load during plugin
initialization.

#### Scenario: Plugin initialization surfaces a rule-configuration failure
- **WHEN** the secret-scanner rule configuration fails to load while the
  plugin is starting up
- **THEN** an error-level log entry is produced and plugin initialization
  does not silently succeed with scanning disabled

### Requirement: Prescreen Must Not Skip Detectable Content
The system MAY skip the full secret scan for output that no anchor-based
detection rule would flag, but SHALL run the full secret scan on any
output that at least one anchor-based detection rule would flag. The
high-entropy detection rule (see `high-entropy-secret-detection`) has no
literal anchor and is therefore exempt from this prescreen — it SHALL
always run as part of the full secret scan, regardless of the prescreen's
outcome.

#### Scenario: Prescreen does not skip a positive fixture for any rule
- **GIVEN** a fixture string known to trigger a specific anchor-based
  detection rule
- **WHEN** the prescreen check is evaluated against that fixture
- **THEN** the prescreen indicates the output requires the full scan for
  every anchor-based detection rule the system supports

#### Scenario: High-entropy detection always runs regardless of the prescreen
- **GIVEN** output text that contains no substring any anchor-based rule
  requires
- **WHEN** the output is scanned
- **THEN** the high-entropy detection rule still evaluates the output for
  high-entropy substrings

### Requirement: Annotate Model On Redaction
The system SHALL append a note to a tool's output when a redaction occurred,
instructing that a redaction placeholder must never be written back to a
file, command, or message, and SHALL NOT append this note when no redaction
occurred. When a tool's output is delivered as multiple discrete text
segments, the system SHALL append exactly one such note, on the last
segment in which a redaction occurred, covering the combined redaction
count and rule identifiers across every affected segment.

#### Scenario: Appends annotation exactly once after a redaction
- **WHEN** one or more secrets are redacted in a tool's output
- **THEN** the returned output contains exactly one annotation, appended
  after all redaction placeholders, warning against writing a placeholder
  back to a file, command, or message

#### Scenario: Does not append annotation when no redaction occurred
- **WHEN** no secret is found in a tool's output
- **THEN** the returned output contains no annotation text

#### Scenario: Single annotation across a multi-segment output
- **WHEN** redactions occur in more than one text segment of the same
  multi-segment tool output
- **THEN** exactly one annotation is appended, on the last segment in which
  a redaction occurred, reporting the combined total count and the union
  of rule identifiers across all affected segments, rather than one
  annotation per segment

### Requirement: Never Log Redacted Secret Values
The system SHALL log, on redaction, only the tool name, the count of
redactions, and the identifiers of the detection rules that matched — and
SHALL NOT log the matched secret text or any scanner-provided message that
could contain it.

#### Scenario: Redaction log entry omits the secret value
- **WHEN** a redaction occurs and a log entry is produced
- **THEN** the log entry contains the tool name, redaction count, and rule
  identifiers, and contains neither the matched secret substring nor the
  underlying scanner finding message

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
error body never reaches the LLM. The system SHALL bound the total volume of text scanned
within a single tool result's metadata, so that an unusually large or
deeply nested metadata value cannot make the scan itself unbounded.

#### Scenario: Empty output is left unchanged
- **WHEN** a tool's output is an empty string
- **THEN** the output is returned unchanged and the secret scanner is not
  invoked

#### Scenario: Non-string output is left unchanged
- **WHEN** a tool's output is not a string value
- **THEN** the output is returned unchanged and the secret scanner is not
  invoked

#### Scenario: A structured output's nested duplicate-text field is scanned
- **WHEN** a tool's output value is a structured (non-string) record whose
  own nested string field duplicates the same text already exposed
  elsewhere in the tool's result, and that nested field contains a
  detectable secret
- **THEN** the nested field's secret is redacted, every other field of the
  structured record is left unchanged, and the record's own type (a
  structured value, not a string) is preserved

#### Scenario: Non-text segment of a multi-segment output is left untouched
- **WHEN** one of a tool's discrete output segments is a reference to
  external content (e.g. a file) rather than inline text
- **THEN** that segment is left completely unmodified and is never passed
  to the secret scanner

#### Scenario: Output of an unsuccessful tool invocation IS scanned
- **WHEN** a tool invocation did not complete successfully (it errored) and
  its error payload contains a detectable secret
- **THEN** that secret is replaced with a redaction placeholder before the
  error reaches the LLM

#### Scenario: A secret in the tool result's metadata is redacted
- **WHEN** a tool result's metadata contains a string field with a
  detectable secret
- **THEN** that field's secret is replaced with a redaction placeholder,
  every other field of the metadata (and the rest of the tool result) is
  left unchanged, and the metadata's own structure (an object, not a
  string) is preserved

#### Scenario: An unusually large structured result does not block indefinitely
- **GIVEN** a tool result whose structured fields together contain an
  unusually large volume of text
- **WHEN** the result is scanned
- **THEN** scanning completes without hanging, redacting every detectable
  secret within the bounded volume scanned
