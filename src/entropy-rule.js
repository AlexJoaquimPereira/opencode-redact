// Shannon-entropy-based detection of secret-shaped substrings that no
// vendor-pattern rule can catch. Implemented as a real secretlint rule
// module (SecretLintRuleCreator), registered directly into a composed
// config by src/secretlint.js rather than resolved from an npm package.
// See design.md D3-D6 for the full derivation and rationale behind every
// constant and decision below — this file follows that design closely and
// should not be re-derived from first principles without re-reading it.

// D3: candidates are maximal runs of the union of the standard-base64,
// base64url, and hex alphabets, plus padding. Maximal runs are pairwise
// disjoint by construction.
const CANDIDATE_RUN_PATTERN = /[A-Za-z0-9+/=_-]+/g;

// spec: openspec/specs/high-entropy-secret-detection/spec.md
// Quotes and brackets terminate spans, including Markdown backticks.
// Commas and semicolons remain valid URL/path content.
const URL_SPAN_PATTERN = /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s"'`()[\]{}<>]+/g;
const PATH_SPAN_PATTERN =
  /(?<![^\s"'`()[\]{}<>])(?:[A-Za-z]:[\\/]|(?:\.\.?|~)[\\/]|\\\\|\/)[^\s"'`()[\]{}<>]*/g;
const VALUE_TOKEN_PATTERN = /[^\s"'`()[\]{}<>,;]+/g;
const NUMERIC_VALUE_PATTERN = /^(?:[A-Za-z_$][\w$]*[=:])?([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)$/;

const HEX_CLASS_PATTERN = /^[0-9a-fA-F]+$/;
const BASE64_CLASS_PATTERN = /^[A-Za-z0-9+/=_-]+$/;

// D4: thresholds are detect-secrets' published defaults.
const HEX_THRESHOLD = 3.0;
const BASE64_THRESHOLD = 4.5;

// D4: length floor derived from the threshold (H <= log2(L), so H > T
// requires L > 2^T), never hard-coded separately, so the two can never
// drift apart.
const HEX_MIN_LENGTH = Math.floor(2 ** HEX_THRESHOLD) + 1; // 9
const BASE64_MIN_LENGTH = Math.floor(2 ** BASE64_THRESHOLD) + 1; // 23

/**
 * Shannon entropy (bits per character) over `text`'s own empirical
 * character distribution: H = -Sum (n_i/L) * log2(n_i/L) over the
 * distinct characters of the run. Order-independent — a permutation of
 * the same multiset of characters always yields the same value.
 */
export function shannonEntropy(text) {
  if (text.length === 0) {
    return 0;
  }
  const counts = new Map();
  for (const char of text) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  const length = text.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/**
 * Returns true when `run` (an object with `start`/`end`) falls entirely
 * within at least one of `spans`.
 */
function isWithinAnySpan(run, spans) {
  return spans.some((span) => run.start >= span.start && run.end <= span.end);
}

/**
 * Finds every URL-shaped span in `text`: an RFC 3986-shaped scheme
 * (letter, then letters/digits/`+`/`.`/`-`) followed by `://` and every
 * non-whitespace, non-quote, non-bracket character after it.
 */
export function findUrlSpans(text) {
  const spans = [];
  for (const match of text.matchAll(URL_SPAN_PATTERN)) {
    spans.push({ start: match.index, end: match.index + match[0].length });
  }
  return spans;
}

/**
 * Finds every anchored filesystem-path-shaped span in `text`: a POSIX
 * absolute path, Windows drive or UNC path, or dot/home-relative path
 * using either separator, anchored at a boundary or the start of text.
 */
export function findPathSpans(text) {
  const spans = [];
  for (const match of text.matchAll(PATH_SPAN_PATTERN)) {
    spans.push({ start: match.index, end: match.index + match[0].length });
  }
  return spans;
}

function findNumericSpans(text) {
  const spans = [];
  for (const token of text.matchAll(VALUE_TOKEN_PATTERN)) {
    const number = NUMERIC_VALUE_PATTERN.exec(token[0])?.[1];
    if (number === undefined) {
      continue;
    }
    const end = token.index + token[0].length;
    spans.push({ start: end - number.length, end });
  }
  return spans;
}

// Subtract, rather than discard overlapping runs: a token can begin
// outside an exemption and continue into a URL scheme without a break.
// Spans must be sorted by start; overlapping spans are supported.
function subtractSpans(runs, spans) {
  const fragments = [];
  for (const run of runs) {
    let start = run.start;
    for (const span of spans) {
      if (span.end <= start || span.start >= run.end) {
        continue;
      }
      if (span.start > start) {
        fragments.push({ start, end: span.start, text: run.text.slice(start - run.start, span.start - run.start) });
      }
      start = Math.max(start, span.end);
      if (start >= run.end) {
        break;
      }
    }
    if (start < run.end) {
      fragments.push({ start, end: run.end, text: run.text.slice(start - run.start) });
    }
  }
  return fragments;
}

/**
 * Returns every maximal run of the candidate charset in `text`, in source
 * order, as `{ start, end, text }`. Disjoint by construction.
 *
 * Slash splitting is retained for this exported helper's default behavior:
 * runs contained within URL/path spans are split into slash-delimited segments.
 * The scoring caller subsequently subtracts those spans entirely.
 * `separatorSpans` supplies containment regions for splitting, not exclusions;
 * callers may reuse broader precomputed spans (numeric spans contain no `/`).
 */
export function findCandidateRuns(text, separatorSpans = [...findUrlSpans(text), ...findPathSpans(text)]) {
  const runs = [];
  for (const match of text.matchAll(CANDIDATE_RUN_PATTERN)) {
    const start = match.index;
    const runText = match[0];
    const end = start + runText.length;
    if (runText.includes("/") && isWithinAnySpan({ start, end }, separatorSpans)) {
      let segmentStart = start;
      for (const segment of runText.split("/")) {
        if (segment.length > 0) {
          runs.push({ start: segmentStart, end: segmentStart + segment.length, text: segment });
        }
        segmentStart += segment.length + 1; // +1 for the consumed "/" delimiter
      }
      continue;
    }
    runs.push({ start, end, text: runText });
  }
  return runs;
}

/**
 * Classifies a run's character set, most-specific-first (every hex run is
 * also a subset of the base64 alphabet, so hex must be checked first or
 * its threshold is unreachable). Returns `null` for a run outside both
 * alphabets — unreachable given `findCandidateRuns`' own tokenization, but
 * kept as a defensive branch.
 */
export function classifyRun(run) {
  if (HEX_CLASS_PATTERN.test(run)) {
    return { charset: "hex", threshold: HEX_THRESHOLD, minLength: HEX_MIN_LENGTH };
  }
  if (BASE64_CLASS_PATTERN.test(run)) {
    return { charset: "base64", threshold: BASE64_THRESHOLD, minLength: BASE64_MIN_LENGTH };
  }
  return null;
}

// D5: every allowlist predicate is fully anchored to the entire run so a
// run merely *containing* an exempt shape (e.g. a UUID prefix glued to a
// real secret) is never exempted.
//
// Shape #1 is case-uniform only: entirely lowercase or entirely uppercase
// hex, at the lengths git actually renders (7-12, abbreviated; 40, full)
// plus common digest lengths (32/40/64/128). A mixed-case run at one of
// these lengths is not a rendered git id or digest — every common tool
// renders hex in one case — so it is deliberately left scored normally.
const GIT_OR_DIGEST_HEX_PATTERN =
  /^(?:[0-9a-f]{7,12}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128}|[0-9A-F]{7,12}|[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}|[0-9A-F]{128})$/;
// Shape #2: UUID. Case-insensitive — the dash structure is already
// specific enough that a credential is not plausibly UUID-shaped by
// accident.
const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
// Shape #3: Subresource Integrity / lockfile `integrity` digest
// (`sha256-<base64>`). Only the prefixed form is exempt — a bare padded
// base64 digest is indistinguishable from a base64-encoded API secret and
// is deliberately NOT exempted.
const SRI_PATTERN = /^sha(?:1|256|384|512)-[A-Za-z0-9+/_-]+={0,2}$/;
// Shape #4: opencode-generated identifier (`ses_`, `msg_`, ...): a known
// prefix, an underscore, then exactly 26 base-62 characters. Anchored to the
// whole run so a secret glued onto an identifier is still reported.
const OPENCODE_ID_PATTERN =
  /^(?:ses|msg|prt|per|psv|frm|wrk|evt|sh|cred|pty|con)_[0-9A-Za-z]{26}$/;

/**
 * Returns true when `run` matches one of the anchored allowlist shapes
 * (case-uniform git object id / hash digest, UUID, or SRI hash) and
 * should never be reported, regardless of its measured entropy.
 */
export function isAllowlistedRun(run) {
  return (
    GIT_OR_DIGEST_HEX_PATTERN.test(run) ||
    UUID_PATTERN.test(run) ||
    SRI_PATTERN.test(run) ||
    OPENCODE_ID_PATTERN.test(run)
  );
}

// D5 #4: a JWT cannot be matched as a single candidate run (`.` is not in
// the run charset), so it is detected via a separate pre-pass over the
// raw content. The `d` (hasIndices) flag exposes each match's absolute
// character offsets via `match.indices`, including the named `sig` group.
const JWT_SPAN_PATTERN = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.(?<sig>[A-Za-z0-9_-]*)/dg;

/**
 * Finds every JWT-shaped span (three period-separated base64url segments,
 * header beginning `eyJ`) in `text`. For each span, returns
 * `{ start, end, signatureRange }` where `signatureRange` is the absolute
 * `{ start, end }` of the signature (third) segment, or `null` when that
 * segment is empty (an unsigned, `alg: none`-style token).
 */
export function findJwtSpans(text) {
  const spans = [];
  for (const match of text.matchAll(JWT_SPAN_PATTERN)) {
    const [fullStart, fullEnd] = match.indices[0];
    const [sigStart, sigEnd] = match.indices.groups.sig;
    const signatureRange = sigEnd > sigStart ? { start: sigStart, end: sigEnd } : null;
    spans.push({ start: fullStart, end: fullEnd, signatureRange });
  }
  return spans;
}

// --- Short password-shaped detection path (independent of the base64/hex
// path above) --- see the add-short-password-secret-detection change's
// design.md for the full derivation of every constant below.
//
// A second, independent tokenization pass over an expanded charset: the
// base64/hex path above never even sees these characters, so a typed
// password containing punctuation (`Tr0ub4dor!23`) would otherwise split
// into unrecognizable fragments. Deliberately NOT merged into
// CANDIDATE_RUN_PATTERN above — widening that pattern would shift the
// existing path's own run boundaries and invalidate its calibration.
const PASSWORD_CANDIDATE_PATTERN = /[A-Za-z0-9!#$%^+~@_-]+/g;

// Calibrated threshold: the highest entropy an all-distinct-character
// ordinary identifier can reach at length 13 is log2(13) ≈ 3.7004, and the
// lowest an all-distinct-character string at length 14 can reach is
// log2(14) ≈ 3.8074 — the midpoint of that admissible interval is chosen
// so the floor and the threshold cannot be tuned independently. This
// threshold, on its own, does NOT separate a random password from an
// ordinary camelCase/PascalCase identifier of the same length (both hit
// the same log2(length) entropy ceiling) — see the mandatory
// character-class-run cap below, which is equally load-bearing.
const SHORT_THRESHOLD = 3.75;
const SHORT_MIN_LENGTH = Math.floor(2 ** SHORT_THRESHOLD) + 1; // 14
const SHORT_MAX_LENGTH = BASE64_MIN_LENGTH - 1; // 22 — the existing base64 path takes over at 23+

const LOWERCASE_PATTERN = /[a-z]/;
const UPPERCASE_PATTERN = /[A-Z]/;
// Rejects any run of 4+ consecutive characters from the same character
// class (lowercase / uppercase / digit / symbol). This is what actually
// separates a random password from an ordinary identifier: a real
// dependency identifier like `rightHandSymbols` clears the entropy
// threshold above but contains a 5-character all-lowercase run (`right`)
// and is correctly rejected here; a genuine password with the same
// entropy but no such run survives.
//
// The {n} quantifier is built from MAX_CLASS_RUN + 1 (not written as a
// separate literal 4) so the two constants can never drift apart.
const MAX_CLASS_RUN = 3;
const LONG_CLASS_RUN_QUANTIFIER = MAX_CLASS_RUN + 1;
const LONG_CLASS_RUN_PATTERN = new RegExp(
  `[a-z]{${LONG_CLASS_RUN_QUANTIFIER}}|[A-Z]{${LONG_CLASS_RUN_QUANTIFIER}}|[0-9]{${LONG_CLASS_RUN_QUANTIFIER}}|[!#$%^+~@_-]{${LONG_CLASS_RUN_QUANTIFIER}}`,
);

/**
 * Returns every maximal run of the password-shaped charset in `text`, in
 * source order, as `{ start, end, text }`. Independent of
 * `findCandidateRuns` — does not affect, and is not affected by, the
 * base64/hex tokenization pass.
 */
export function findPasswordCandidateRuns(text) {
  const runs = [];
  for (const match of text.matchAll(PASSWORD_CANDIDATE_PATTERN)) {
    runs.push({ start: match.index, end: match.index + match[0].length, text: match[0] });
  }
  return runs;
}

/**
 * Returns true when `run` contains at least one lowercase letter AND at
 * least one uppercase letter. Mandatory precondition for the short
 * password path — on its own, not sufficient (see `hasLongClassRun` and
 * the entropy threshold).
 */
export function hasLetterCaseMix(run) {
  return LOWERCASE_PATTERN.test(run) && UPPERCASE_PATTERN.test(run);
}

/**
 * Returns true when `run` contains a run of 4 or more consecutive
 * characters from the same character class (lowercase, uppercase, digit,
 * or the password-punctuation symbols). A `true` result means the
 * candidate must be REJECTED — see design.md for why this is required
 * alongside, not instead of, the entropy threshold.
 */
export function hasLongClassRun(run) {
  return LONG_CLASS_RUN_PATTERN.test(run);
}

/**
 * Orchestrates the full per-message detection pass: the JWT pre-pass
 * (reporting only non-empty signature segments, unconditionally), then
 * generic entropy scoring of every candidate run not inside a JWT span and
 * not allowlist-exempt. Returns findings in source order as
 * `{ start, end }` — no ruleId or message; the caller (the rule module
 * below) attaches those.
 */
export function findHighEntropyFindings(text) {
  const jwtSpans = findJwtSpans(text);
  const scoringExemptions = [...findUrlSpans(text), ...findPathSpans(text), ...findNumericSpans(text)]
    .sort((a, b) => a.start - b.start);
  const findings = [];

  for (const span of jwtSpans) {
    if (span.signatureRange) {
      findings.push({ start: span.signatureRange.start, end: span.signatureRange.end });
    }
  }

  const existingRuns = subtractSpans(findCandidateRuns(text, scoringExemptions), scoringExemptions);
  const allowlistedSpans = [];

  for (const run of existingRuns) {
    if (isWithinAnySpan(run, jwtSpans)) {
      continue;
    }
    if (isAllowlistedRun(run.text)) {
      allowlistedSpans.push(run);
      continue;
    }
    const classification = classifyRun(run.text);
    if (!classification || run.text.length < classification.minLength) {
      continue;
    }
    if (shannonEntropy(run.text) > classification.threshold) {
      findings.push({ start: run.start, end: run.end });
    }
  }

  // Short password-shaped path: independent tokenization, but excludes any
  // candidate already governed by the JWT pre-pass or the existing path's
  // allowlist (e.g. a Subresource Integrity hash's digest fragment), so it
  // cannot reintroduce a false positive an existing exemption already
  // rules out, nor double-report a JWT's header/payload.
  const exemptSpans = [...jwtSpans, ...allowlistedSpans];

  for (const run of subtractSpans(findPasswordCandidateRuns(text), scoringExemptions)) {
    if (run.text.length < SHORT_MIN_LENGTH || run.text.length > SHORT_MAX_LENGTH) {
      continue;
    }
    if (isWithinAnySpan(run, exemptSpans)) {
      continue;
    }
    if (!hasLetterCaseMix(run.text)) {
      continue;
    }
    if (hasLongClassRun(run.text)) {
      continue;
    }
    if (shannonEntropy(run.text) > SHORT_THRESHOLD) {
      findings.push({ start: run.start, end: run.end });
    }
  }

  findings.sort((a, b) => a.start - b.start);

  // A run can independently clear both the existing hex path and the new
  // password path (e.g. a mixed-case, 14-22 character, all-hex run whose
  // entropy exceeds both 3.0 and 3.75) — the two tokenization passes are
  // deliberately independent and neither is aware of the other's result.
  // De-duplicate identical ranges here so this function's own contract is
  // "one finding per distinct range", rather than relying on
  // `mergeIntervals` downstream (in src/redact.js) to absorb the
  // duplicate silently.
  const deduplicated = [];
  for (const finding of findings) {
    const previous = deduplicated[deduplicated.length - 1];
    if (previous && previous.start === finding.start && previous.end === finding.end) {
      continue;
    }
    deduplicated.push(finding);
  }
  return deduplicated;
}

// D6: the message is a constant with no interpolated props. It never
// contains the matched token, and passing no second argument to the
// translator keeps `data` as `undefined` — sidestepping a real engine
// trap where `maskSecrets` string-replaces every string value throughout
// the message, which would silently corrupt a prop as innocuous as
// `CHARSET: "base64"`.
const MESSAGES = {
  HighEntropySecret: {
    en: () => "found a high-entropy string that may be a secret",
  },
};

/**
 * The secretlint rule module. Registered directly by src/secretlint.js
 * into a composed config (not resolved from an npm package) with config
 * entry `id: "high-entropy"` — that id, not `meta.id`, is what secretlint
 * core attaches as `message.ruleId`, so `shortRuleId` (which only strips
 * an `@secretlint/secretlint-rule-` prefix) passes it through untouched:
 * `***REDACTED:high-entropy***`, or `***REDACTED:aws+high-entropy***` when
 * merged with an anchored-rule finding.
 */
export const creator = {
  messages: MESSAGES,
  meta: {
    id: "high-entropy",
    type: "scanner",
    recommended: false,
    supportedContentTypes: ["text"],
  },
  create(context) {
    const t = context.createTranslator(MESSAGES);
    return {
      file(source) {
        for (const finding of findHighEntropyFindings(source.content)) {
          context.report({
            message: t("HighEntropySecret"),
            range: [finding.start, finding.end],
          });
        }
      },
    };
  },
};
