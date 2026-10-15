# Proposal

## Why

User-authored `noredact` blocks survive the V2 prompt hook but can be redacted by later request-assembly hooks, defeating the documented exemption before the model receives the message. Restore that exemption across rescans without exempting any additional message roles or disabling request-payload protection.

## What Changes

- Honor the existing fence grammar for text blocks in messages whose role is exactly `user` during V2 `context`, `generate`, and `compaction` handling.
- Treat this as a user-role exemption, not proof of human authorship: synthetic messages, expanded files, and compaction summaries represented as user-role text also receive it. The user explicitly accepted this boundary; no provenance tracking is introduced.
- Continue scanning text outside well-formed fences and all text inside malformed or unterminated fences.
- Keep system prompts, system-role messages, assistant-role messages, tool-role messages, and tool output fence-unaware; unknown or missing roles receive no exemption.
- Add chained-hook regression coverage and clarify the persistent V2 user-message exemption in the README.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `request-payload-redaction`: preserve the existing user-message fence exemption during every supported request-assembly stage while retaining scanning for non-user content.

## Impact

- Implementation: `src/plugin.v2.js`.
- Tests: `test/plugin-conformance.test.js`.
- Documentation: `README.md`; archive merges the delta into `openspec/specs/request-payload-redaction/spec.md`.
- Reuse the existing scanner and fence parser; no new configuration, dependencies, public API, or persisted metadata.
- Unchanged: V1 hooks, detection rules, tool-output scanning, non-text content handling, annotation aggregation, and fail-open behavior. No vendor installation edits, release, or service restart are included.

## Proposal Review Dispositions

- Accepted the agent-engineer and security reviewers' role/provenance concern. Local SDK text parts have no standard authorship flag; the user chose to retain the role-based exemption after the broader impact was explained.
- Accepted strict `user` role matching, default-off fence handling for shared scanning paths, and per-text-block parsing. Fences cannot span blocks or messages.
- Accepted regression coverage for chained and repeated rescans, mixed exempt/non-exempt text, malformed fences, non-user roles, system segments, annotation aggregation, and non-text preservation. Existing tool-output protection remains unchanged.
- Kept request-stage annotation wording and aggregation unchanged; changing annotation semantics is outside this fix.
