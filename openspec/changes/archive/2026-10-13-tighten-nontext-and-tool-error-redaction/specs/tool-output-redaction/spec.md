## MODIFIED Requirements

### Requirement: Handle Non-Scannable Output Gracefully

The system SHALL leave tool output unmodified, without invoking the secret
scanner, when that output is empty, absent, or not a string, except that
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
successfully, preserving the host error's identity and prototype.
Structured traversal of V2 metadata, errors, history inputs, and history
result values, including string inputs, SHALL scan at most 200000 characters
and visit at most 10000 values per tool-result scan or request-hook invocation, entering at most 128 nested
containers along a path. A string exceeding the remaining
budget, a cyclic back-edge, or a branch beyond the depth limit SHALL remain
unmodified. Each distinct skip reason SHALL produce a payload-free warning
once per tool-result scan or request-hook invocation without preventing eligible independent siblings from being scanned.
Exhausting the value-visit budget SHALL leave all remaining branches unchanged.
Copy-on-write traversal SHALL preserve property descriptors, throwing accessors,
and array holes while continuing to scan readable siblings.
Copy-on-write traversal SHALL scan only plain objects (including null-prototype
records) and arrays. Other prototypes SHALL remain untouched, including secrets
in their own fields. Host execution errors SHALL still be scanned in place.
V1 metadata scanning SHALL skip containers at depth 128, report that skip without
payloads, and run independently of output-scan failures.
These fail-open limits do not apply to ordinary text content blocks or
the narrowly targeted duplicate-output string field.

#### Scenario: Empty output is left unchanged
- **WHEN** a tool's output is an empty string
- **THEN** the output is returned unchanged and the secret scanner is not invoked

#### Scenario: Non-string output is left unchanged
- **WHEN** a tool's output is not a string value
- **THEN** the output is returned unchanged and the secret scanner is not invoked

#### Scenario: A structured output's nested duplicate-text field is scanned
- **WHEN** a tool's output value is a structured record whose own nested string field duplicates text already exposed elsewhere in the result and contains a detectable secret
- **THEN** that secret is redacted, other fields stay unchanged, and the output remains structured

#### Scenario: Non-text segment of a multi-segment output is left untouched
- **WHEN** a discrete output segment references external content rather than inline text
- **THEN** that segment is left completely unmodified and is never passed to the scanner

#### Scenario: Output of an unsuccessful tool invocation IS scanned
- **WHEN** a tool invocation errors and its error payload contains a detectable secret within the traversal bounds
- **THEN** that secret is replaced before the error reaches the LLM, retaining the error's identity and prototype

#### Scenario: A secret in the tool result's metadata is redacted
- **WHEN** a tool result's metadata contains a string field with a detectable secret within the traversal bounds
- **THEN** that secret is redacted, other fields and the rest of the result stay unchanged, and metadata remains structured

#### Scenario: An unusually large structured result does not block indefinitely
- **GIVEN** structured metadata or an error whose strings exceed the scan budget
- **WHEN** the result is scanned
- **THEN** an oversized leaf is preserved, a payload-free budget warning is emitted once, and later siblings fitting the remaining budget are still redacted

#### Scenario: Cyclic and deep structured branches are skipped independently
- **WHEN** metadata or a host error contains a cyclic back-edge or more than 128 nested containers
- **THEN** the affected branch is preserved, a payload-free cycle or depth warning is emitted once, and independent siblings are still redacted

#### Scenario: Shared graphs cannot exhaust traversal work
- **WHEN** structured metadata, an error, or history contains a shared graph requiring more than 10000 value visits
- **THEN** traversal stops at that bound, emits one payload-free visits warning, and leaves unvisited values unchanged

#### Scenario: Throwing properties do not suppress readable siblings
- **WHEN** a structured value contains a throwing getter alongside a detectable secret
- **THEN** the readable secret is redacted, the getter is retained, and copy-on-write preserves property descriptors and array holes

#### Scenario: Non-plain structured values are left untouched
- **WHEN** a copy-on-write traversal encounters a Date, Map, Error, or other class instance alongside a plain field containing a secret
- **THEN** the instance is preserved by reference without scanning its fields, while the eligible plain field is redacted

#### Scenario: V1 metadata depth skips preserve independent redactions
- **WHEN** V1 metadata contains a branch reaching depth 128 alongside readable secret-bearing siblings
- **THEN** the deep branch remains unchanged, the siblings are redacted and counted, and a payload-free depth warning is emitted

#### Scenario: V1 metadata scanning is isolated from output failures
- **WHEN** reading or processing V1 tool output fails and its metadata contains a detectable secret
- **THEN** the metadata is still scanned and redacted, and errors are logged without payloads

#### Scenario: V1 metadata redacts own prototype keys without changing prototypes
- **WHEN** V1 metadata has an own `__proto__` string field containing a detectable secret
- **THEN** that field is redacted while the metadata prototype and own-property status are preserved

#### Scenario: Read-only host error fields are preserved while writable siblings are redacted
- **WHEN** a host execution error has a read-only secret-bearing field alongside a writable secret-bearing field
- **THEN** the writable field is redacted, the read-only field is preserved, and the original error is returned
