# Proposal

## Why

Unquoted filesystem paths in assignments can be mistaken for high-entropy secrets, replacing harmless command text and causing failures when that text is reused.

## What Changes

- Extend anchored filesystem-path exemptions to values immediately after token-boundary identifier assignments (`NAME=`); embedded equals signs do not create assignment boundaries.
- Preserve entropy detection for unanchored slash-containing credentials, explicit credential-pattern rules, and JWT signatures.

## Capabilities

### Modified Capabilities

- `high-entropy-secret-detection`: assignment-aware filesystem-path recognition.

## Impact

Changes are limited to `src/entropy-rule.js`, `test/entropy-rule.test.js`, and this capability's OpenSpec artifacts. Entropy thresholds, redaction expansion, runtime hooks, dependencies, and configuration remain unchanged.
