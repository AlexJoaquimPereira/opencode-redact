// Pure redaction core. Imports nothing from secretlint — the linter is always
// injected as a parameter, so this module is testable without invoking a real
// scanner. See design.md D1.

// Structural delimiter characters that stop expansion the same way
// whitespace does. See openspec/specs/tool-output-redaction/spec.md for
// the boundary contract. These never appear inside any
// secret shape this plugin can detect:
//   - this plugin's own entropy candidate charsets (CANDIDATE_RUN_PATTERN,
//     PASSWORD_CANDIDATE_PATTERN in entropy-rule.js) exclude all of these
//     characters at tokenization time, before scoring even starts;
//   - every reachable secretlint vendor-pattern rule's own regex match
//     already reports a range terminating at, or beyond, the true secret
//     boundary, so expansion (which only ever grows outward) never needs
//     to cross one of these characters to reach the rest of a real secret.
// This second half of the invariant depends on the installed secretlint /
// @secretlint/secretlint-rule-preset-recommend version's rule
// implementations continuing to report complete ranges — re-verify this
// comment's claim on any bump of that dependency.
// `:` `;` `(` `)` `<` `>` `|` `&` `=` `?` `/` are deliberately excluded:
// several of those can legitimately appear inside a URL, database
// connection string, or password value, so treating them as boundaries
// risks truncating part of a real secret.
const BOUNDARY_PATTERN = /[\s"'`,{}[\]]/;

/**
 * Expands [start, end) outward to the nearest surrounding whitespace or
 * structural delimiter character (quote, comma, or bracket — see
 * `BOUNDARY_PATTERN` above) so a finding whose reported range only
 * partially covers its secret does not leave a fragment of that secret in
 * the output. Never expands past the bounds of `text`.
 */
export function expandToTokenBoundaries(text, start, end) {
  let newStart = start;
  while (newStart > 0 && !BOUNDARY_PATTERN.test(text[newStart - 1])) {
    newStart -= 1;
  }
  let newEnd = end;
  while (newEnd < text.length && !BOUNDARY_PATTERN.test(text[newEnd])) {
    newEnd += 1;
  }
  return [newStart, newEnd];
}

/**
 * Validates and expands each message's range into a token-boundary-expanded
 * interval. Malformed ranges (non-integer, inverted, or out of bounds) are
 * dropped rather than repaired, and never throw.
 */
export function normalizeRanges(text, messages) {
  const intervals = [];
  for (const message of messages) {
    const range = message.range;
    if (!Array.isArray(range) || range.length !== 2) {
      continue;
    }
    const [start, end] = range;
    if (
      !Number.isInteger(start) ||
      !Number.isInteger(end) ||
      start < 0 ||
      end <= start ||
      end > text.length
    ) {
      continue;
    }
    const [expandedStart, expandedEnd] = expandToTokenBoundaries(text, start, end);
    intervals.push({ start: expandedStart, end: expandedEnd, ruleIds: new Set([message.ruleId]) });
  }
  return intervals;
}

/**
 * Sorts intervals and merges any that overlap or exactly touch into a single
 * interval, unioning their rule ids. `<=` (not `<`) is used for the touch
 * comparison so two findings sitting back-to-back in the same unbroken
 * non-whitespace run produce one placeholder, not two adjacent ones.
 */
export function mergeIntervals(intervals) {
  if (intervals.length === 0) {
    return [];
  }
  const sorted = [...intervals].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged = [{ ...sorted[0], ruleIds: new Set(sorted[0].ruleIds) }];
  for (let i = 1; i < sorted.length; i += 1) {
    const next = sorted[i];
    const current = merged[merged.length - 1];
    if (next.start <= current.end) {
      current.end = Math.max(current.end, next.end);
      for (const ruleId of next.ruleIds) {
        current.ruleIds.add(ruleId);
      }
    } else {
      merged.push({ ...next, ruleIds: new Set(next.ruleIds) });
    }
  }
  return merged;
}

/**
 * Strips the common secretlint rule package prefix for a short, readable
 * placeholder label. Falls back to the raw id when the prefix is absent.
 */
export function shortRuleId(ruleId) {
  const prefix = "@secretlint/secretlint-rule-";
  return ruleId.startsWith(prefix) ? ruleId.slice(prefix.length) : ruleId;
}

function placeholderFor(ruleIds) {
  const labels = [...new Set([...ruleIds].map(shortRuleId))].sort();
  return `***REDACTED:${labels.join("+")}***`;
}

/**
 * Replaces each merged interval's span in `text` with a redaction
 * placeholder in a single left-to-right pass. Intervals must be sorted and
 * disjoint (mergeIntervals' output satisfies this) so every slice is
 * forward-only and no index is invalidated by an earlier replacement.
 */
export function spliceRedactions(text, mergedIntervals) {
  if (mergedIntervals.length === 0) {
    return text;
  }
  const parts = [];
  let cursor = 0;
  for (const { start, end, ruleIds } of mergedIntervals) {
    parts.push(text.slice(cursor, start), placeholderFor(ruleIds));
    cursor = end;
  }
  parts.push(text.slice(cursor));
  return parts.join("");
}

// Opening fence line: 0-3 leading spaces, a run of 3+ backticks, then an
// info string that (after trimming spaces/tabs) is checked to be exactly
// "noredact" — see the token check below. See design.md D4.
const OPEN_FENCE_LINE_PATTERN = /^[ ]{0,3}(`{3,})[ \t]*([^\s]*)[ \t]*$/;

/**
 * Returns the opening fence's backtick-run length when `lineContent`
 * (a single line, terminator already stripped) is a valid noredact opening
 * fence line, or `null` otherwise. The info-string token is required to be
 * exactly "noredact", ASCII case-insensitive — matched with an explicit
 * `[A-Za-z]` check (not a Unicode-aware `toLowerCase`) so a homoglyph or
 * case-folding trick cannot open a fence (design.md D4 row 5).
 */
function matchOpenFence(lineContent) {
  const match = OPEN_FENCE_LINE_PATTERN.exec(lineContent);
  if (!match) {
    return null;
  }
  const [, backticks, token] = match;
  if (!/^[A-Za-z]+$/.test(token) || token.toLowerCase() !== "noredact") {
    return null;
  }
  return backticks.length;
}

/**
 * Returns true when `lineContent` is a valid closing fence line for an
 * opening run of exactly `fenceLength` backticks. The closer's backtick run
 * must match the opener's length EXACTLY (not CommonMark's "closer >=
 * opener") — see design.md D4 row 1.
 */
function matchCloseFence(lineContent, fenceLength) {
  const pattern = new RegExp(`^[ ]{0,3}\`{${fenceLength}}[ \\t]*$`);
  return pattern.test(lineContent);
}

// Strips exactly one trailing line terminator (`\n`, optionally preceded by
// `\r`) from a line for grammar-matching purposes only — the original line,
// terminator included, is always what gets appended to a buffer/segment, so
// reassembly is byte-identical (design.md D4 row 6, D5 invariant 1).
function stripLineTerminatorForMatching(line) {
  return line.replace(/\r?\n$/, "");
}

/**
 * Splits `text` into an ordered array of `{ text, exempt }` segments per the
 * noredact fence grammar (design.md D4). `exempt` segments are fully-formed
 * fenced blocks (opening fence line through closing fence line inclusive)
 * whose content must not be scanned; all other text is `exempt: false`.
 *
 * Two invariants hold for every input (design.md D5), both asserted as
 * properties in test/redact.test.js:
 *   1. Round-trip: `segments.map(s => s.text).join("") === text`.
 *   2. No empty segments are ever emitted.
 *
 * An unterminated opening fence (no matching closer before EOF) is
 * reclassified as non-exempt in its entirety, including the orphan opening
 * fence line — nothing is dropped, nothing is exempted (fail-safe default).
 */
export function splitNoRedactSegments(text) {
  if (typeof text !== "string" || text.length === 0) {
    return [];
  }

  const lines = text.split(/(?<=\n)/);
  const segments = [];

  let plainBuffer = "";
  let exemptBuffer = "";
  let openFenceLength = null; // null when outside a fence

  for (const line of lines) {
    const matchContent = stripLineTerminatorForMatching(line);

    if (openFenceLength === null) {
      const fenceLength = matchOpenFence(matchContent);
      if (fenceLength !== null) {
        if (plainBuffer.length > 0) {
          segments.push({ text: plainBuffer, exempt: false });
          plainBuffer = "";
        }
        openFenceLength = fenceLength;
        exemptBuffer = line;
      } else {
        plainBuffer += line;
      }
    } else if (matchCloseFence(matchContent, openFenceLength)) {
      exemptBuffer += line;
      segments.push({ text: exemptBuffer, exempt: true });
      exemptBuffer = "";
      openFenceLength = null;
    } else {
      exemptBuffer += line;
    }
  }

  if (openFenceLength !== null) {
    // Unterminated opening fence at EOF: reclassify the buffered content
    // (including the orphan opening fence line) as non-exempt.
    plainBuffer += exemptBuffer;
  }
  if (plainBuffer.length > 0) {
    segments.push({ text: plainBuffer, exempt: false });
  }

  return segments;
}

/**
 * Builds the model-facing note appended after redaction, naming the
 * concrete prohibited action (writing a placeholder back) so the model does
 * not corrupt real content on a subsequent write/edit of redacted output.
 */
export function buildAnnotation(count, ruleIds) {
  const labels = [...new Set(ruleIds)].sort().join("+");
  return (
    `[opencode-redact] ${count} secret(s) in this tool output were detected and replaced ` +
    `with ***REDACTED:...*** placeholders (rules: ${labels}). A placeholder is NOT the ` +
    `real value and is NOT part of the underlying file, command output, or response. ` +
    `Never write, copy, echo, or commit a ***REDACTED:...*** placeholder into a file, ` +
    `command, or message — doing so would overwrite real content with this marker. ` +
    `If you need the redacted value, ask the user for it; do not try to recover it.`
  );
}

/**
 * Orchestrates the full detect -> merge -> splice pipeline, WITHOUT
 * appending any model-facing annotation. `lint` is injected so this
 * function is testable with a stub and, through the same seam,
 * integration-testable with the real secretlint linter.
 *
 * Returns `{ text, redactionCount, ruleIds }` — `text` is the original
 * value unchanged whenever nothing is redacted (including on a scanner
 * error, per the fail-open contract; this may be a non-string value such as
 * `undefined`, which is intentionally returned as-is, not coerced), or the
 * redacted string when at least one finding was merged and spliced.
 *
 * Annotation-free by design: two callers build different annotations on top
 * of this shared core — `redactSecrets` (tool output) and
 * `redactUserMessage` (user messages, which additionally applies the
 * `noredact` fence exemption and aggregates across message parts). See
 * design.md D1.
 *
 * Deliberately does NOT apply the anchor-based prescreen itself (see
 * design.md D2) — `lint` is expected to be a composed linter
 * (`createCompositeLinter`, from src/secretlint.js) that gates its own
 * anchored rule bundle behind the prescreen internally while always
 * running the anchor-free high-entropy bundle. Applying the prescreen
 * here, before ever calling `lint`, would prevent the entropy bundle from
 * ever running on anchor-negative text — exactly the class of secret it
 * exists to catch.
 */
export async function scanAndRedact(text, { lint }) {
  if (typeof text !== "string" || text.length === 0) {
    return { text, redactionCount: 0, ruleIds: [] };
  }

  let messages;
  try {
    messages = await lint(text);
  } catch {
    return { text, redactionCount: 0, ruleIds: [] };
  }

  const intervals = normalizeRanges(text, messages);
  const merged = mergeIntervals(intervals);
  if (merged.length === 0) {
    return { text, redactionCount: 0, ruleIds: [] };
  }

  const redacted = spliceRedactions(text, merged);
  const ruleIds = [...new Set(merged.flatMap((interval) => [...interval.ruleIds].map(shortRuleId)))];

  return { text: redacted, redactionCount: merged.length, ruleIds };
}

/**
 * Thin wrapper around `scanAndRedact` for the tool-output redaction path:
 * appends the tool-output annotation after all redaction placeholders when
 * at least one finding was redacted. Behavior-preserving by construction —
 * see the refactor-safety baseline in test/redact-baseline.test.js.
 */
export async function redactSecrets(text, { lint }) {
  const result = await scanAndRedact(text, { lint });
  if (result.redactionCount === 0) {
    return result;
  }

  return {
    text: `${result.text}\n\n${buildAnnotation(result.redactionCount, result.ruleIds)}`,
    redactionCount: result.redactionCount,
    ruleIds: result.ruleIds,
  };
}

/**
 * Orchestrates redaction for a single user-authored (non-synthetic) text
 * part: `splitNoRedactSegments` honors the `noredact` fence, then
 * `scanAndRedact` runs on each non-exempt segment. Exempt segments pass
 * through byte-identical. Results are concatenated in source order;
 * `redactionCount` is summed and `ruleIds` is the de-duplicated, sorted
 * union across all scanned segments.
 *
 * Deliberately does NOT apply a whole-text anchor-based prescreen itself
 * (design.md D2) — same reasoning as `scanAndRedact`: `lint` is expected
 * to be a composed linter that always runs its anchor-free high-entropy
 * bundle, and a prescreen here would suppress that on anchor-negative
 * segments.
 *
 * Deliberately annotation-free (like `scanAndRedact`) — only the
 * `chat.message` hook, which sees every part of a message, can aggregate a
 * single annotation across parts. See `buildUserMessageAnnotation` and
 * design.md D1/D6.
 */
export async function redactUserMessage(text, { lint }) {
  if (typeof text !== "string" || text.length === 0) {
    return { text, redactionCount: 0, ruleIds: [] };
  }

  const segments = splitNoRedactSegments(text);
  const resultParts = [];
  let redactionCount = 0;
  const ruleIdSet = new Set();

  for (const segment of segments) {
    if (segment.exempt) {
      resultParts.push(segment.text);
      continue;
    }
    const scanned = await scanAndRedact(segment.text, { lint });
    resultParts.push(scanned.text);
    redactionCount += scanned.redactionCount;
    for (const ruleId of scanned.ruleIds) {
      ruleIdSet.add(ruleId);
    }
  }

  return {
    text: resultParts.join(""),
    redactionCount,
    ruleIds: [...ruleIdSet].sort(),
  };
}

/**
 * Builds the model-facing note appended once per user message when at
 * least one redaction occurred across its parts. Unlike `buildAnnotation`
 * (tool output, where the model is told to ask the user for the value),
 * this note addresses a redaction of the user's OWN message — re-asking
 * would loop or coach the model toward soliciting a bypass, so it instead
 * instructs the model to say so and stop. Deliberately makes NO mention of
 * the `noredact` fence or any exemption mechanism (design.md's user
 * decision on annotation content) — teaching the model such a convention
 * would teach it a documented bypass of this security control, since
 * `chat.message` also fires for messages the model itself authored (e.g.
 * subagent/task-tool prompts).
 */
export function buildUserMessageAnnotation(count, ruleIds) {
  const labels = [...new Set(ruleIds)].sort().join("+");
  return (
    `[opencode-redact] ${count} secret(s) in this user message were detected and replaced ` +
    `with ***REDACTED:...*** placeholders (rules: ${labels}). A placeholder is NOT the ` +
    `real value and is NOT part of what the user typed. Never write, copy, echo, or commit ` +
    `a ***REDACTED:...*** placeholder into a file, command, or message — doing so would ` +
    `overwrite real content with this marker. Do not attempt to recover, reconstruct, or ` +
    `guess a redacted value; if the task cannot proceed without it, say so and stop.`
  );
}
