## Context

`src/entropy-rule.js` centralizes path recognition in `findPathSpans`; its intervals feed both entropy passes through `scoringExemptions` and `subtractSpans`. The accepted scope is token-boundary identifier-assigned anchored paths, not general assignment parsing or unanchored relative paths. The behavioral contract is in [the delta spec](specs/high-entropy-secret-detection/spec.md).

## Decisions

- Extend the existing path matcher with an optional boundary-anchored identifier-and-equals prefix and a captured path portion. Use ASCII shell-style identifiers: an initial letter or underscore followed by letters, digits, or underscores. Keep the existing boundary assertion before the optional prefix and the existing path anchor immediately after it. This localizes recognition to one matcher without admitting embedded equals as standalone boundaries.
- Return intervals for the captured path only, deriving absolute offsets from the match and prefix length. Keep `findPathSpans`' exported result shape unchanged. This maps to the delta spec's assignment-aware path exemption and exclusion of assignment labels.
- Reuse the existing sorted exemption collection and interval subtraction unchanged. Both scoring passes consume the same path intervals; labels and crossing outside fragments remain in the scoring pipeline. This maps to the delta spec's bounded-exemption contract.
- Keep JWT discovery and reporting independent of entropy exemptions. Explicit credential rules, thresholds, tokenization, and redaction expansion remain separate concerns. These preservation decisions map to the delta spec's retained detection guarantees.
- Reject a separate assignment parser or second path matcher: either adds traversal and duplicates recognition logic without a stated need. Reject broadening the boundary character class to include equals: it loses assignment context.

## Risks

Incorrect capture offsets could exempt labels or truncate paths. No parser, dependency, persistent state, or additional scanning pass is introduced; recovery is confined to the matcher and range calculation.

Assigned opaque secrets starting with `/`, including `//`, are indistinguishable from path-shaped values and are entropy-exempt. Explicit credential rules and JWT detection remain active.
