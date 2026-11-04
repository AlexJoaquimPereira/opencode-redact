# Proposal

## Why

Entropy detection currently mistakes numeric output and high-diversity URL or filesystem-path segments for secrets. Users need these ordinary values preserved without disabling explicit credential detection.

## What Changes

- Exempt complete URL and Linux/Windows filesystem-path spans from entropy-based detection, including its short-password pass.
- Exempt signed integers, decimals, and scientific-notation values from entropy-based detection.
- Leave explicit secret-pattern rules active, including for recognizable credentials embedded in URLs or paths.
- Accept that opaque credentials inside exempt spans will no longer be detected by entropy alone.

## Capabilities

### Modified Capabilities

- `high-entropy-secret-detection`: replace segment-scoring URL/path handling with complete-span exemptions and add numeric preservation.

## Impact

Changes are limited to `src/entropy-rule.js`, `test/entropy-rule.test.js`, `README.md`, and this capability's OpenSpec artifacts. Thresholds, configuration, dependencies, and V1/V2 integration remain unchanged.
