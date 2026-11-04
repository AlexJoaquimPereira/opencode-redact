// spec: openspec/specs/user-message-redaction/spec.md
//
// Tests for splitNoRedactSegments against the fence grammar table in
// design.md D4, plus the two D5 invariants (round-trip, no empty segments)
// asserted as properties over the shared fixture corpus.

import { describe, it, expect } from "vitest";
import { splitNoRedactSegments } from "../src/redact.js";
import { RULE_FIXTURES, GCP_JSON_FIXTURE } from "./fixtures.js";
import { STUB_ENTRIES } from "./corpus.js";

function roundTrips(text) {
  const segments = splitNoRedactSegments(text);
  return segments.map((s) => s.text).join("") === text;
}

function hasNoEmptySegment(text) {
  return splitNoRedactSegments(text).every((s) => s.text.length > 0);
}

const FENCE_SPECIFIC_FIXTURES = [
  "```noredact\nfoo\n```\n",
  "before\n```noredact\nsecret stuff\n```\nafter\n",
  "```noredact\n```\n",
  "```noredact\nfoo\n```",
  "````noredact\n```\nstill inside\n````\n",
  "```noredact\nfoo\n``` unterminated after this",
  "text with no fence at all",
  "```noredact\r\nfoo\r\n```\r\n",
  "```noredact\nfirst\n```\n```noredact\nsecond\n```\n",
  "   ```noredact\n  content\n   ```\n",
];

describe("splitNoRedactSegments — D5 invariants (property tests)", () => {
  const corpusInputs = [
    ...RULE_FIXTURES.map((f) => f.content),
    GCP_JSON_FIXTURE,
    ...STUB_ENTRIES.map((e) => e.input).filter((input) => typeof input === "string"),
    ...FENCE_SPECIFIC_FIXTURES,
    "",
  ];

  it("round-trips every corpus input byte-identically", () => {
    for (const input of corpusInputs) {
      expect(roundTrips(input), `round-trip failed for: ${JSON.stringify(input)}`).toBe(true);
    }
  });

  it("never emits an empty segment for any corpus input", () => {
    for (const input of corpusInputs) {
      expect(hasNoEmptySegment(input), `empty segment emitted for: ${JSON.stringify(input)}`).toBe(true);
    }
  });

  it("returns an empty array for an empty string", () => {
    expect(splitNoRedactSegments("")).toEqual([]);
  });

  it("returns two adjacent exempt segments for back-to-back fenced blocks (segments need not alternate)", () => {
    const text = "```noredact\nfirst\n```\n```noredact\nsecond\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments.map((s) => s.exempt)).toEqual([true, true]);
  });
});

describe("splitNoRedactSegments — D4 grammar table", () => {
  it("row 1: closer length must match the opener exactly — a longer closer does not close it (unterminated -> non-exempt)", () => {
    const text = "```noredact\nfoo\n````\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 1: closer length must match the opener exactly — a shorter closer does not close it (unterminated -> non-exempt)", () => {
    const text = "````noredact\nfoo\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 1: a longer outer fence lets an inner bare fence of a different length pass through exempt", () => {
    const text = "````noredact\n```\nstill inside\n````\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: true }]);
  });

  it("row 2: a tilde fence is not recognised — content is scanned (non-exempt)", () => {
    const text = "~~~noredact\nfoo\n~~~\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 3: 0-3 leading spaces on the opening fence are accepted", () => {
    const text = "   ```noredact\ncontent\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: true }]);
  });

  it("row 3: 4+ leading spaces on the opening fence line disqualify it (non-exempt)", () => {
    const text = "    ```noredact\ncontent\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 3: a leading tab on the opening fence line disqualifies it (non-exempt)", () => {
    const text = "\t```noredact\ncontent\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 3: 0-3 leading spaces on the closing fence line are accepted independently of the opener's indentation", () => {
    const text = "```noredact\ncontent\n   ```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: true }]);
  });

  it("row 4: the info string must be exactly 'noredact' (case-insensitive) — 'NoReDact' is accepted", () => {
    const text = "```NoReDact\ncontent\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: true }]);
  });

  it("row 4: a trailing extra word after 'noredact' is not a fence (e.g. ```noredact json)", () => {
    const text = "```noredact json\ncontent\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 4: a leading extra word before 'noredact' is not a fence (e.g. ```json noredact)", () => {
    const text = "```json noredact\ncontent\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 4: a superstring token is not a fence (e.g. ```noredactx)", () => {
    const text = "```noredactx\ncontent\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 5: a homoglyph info string is not a fence (Cyrillic 'с' in place of 'c')", () => {
    const text = "```noredaСt\ncontent\n```\n".replace("С", "\u0441"); // Cyrillic es (U+0441) in place of ASCII 'c'
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });

  it("row 6: CRLF line endings round-trip byte-identically inside an exempt fence", () => {
    const text = "```noredact\r\nfoo\r\n```\r\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: true }]);
  });

  it("row 7: multiple fences in one part are all recognised, non-fenced text between them is non-exempt", () => {
    const text = "before\n```noredact\nfirst\n```\nmiddle\n```noredact\nsecond\n```\nafter";
    const segments = splitNoRedactSegments(text);
    expect(segments.map((s) => s.exempt)).toEqual([false, true, false, true, false]);
    expect(segments.map((s) => s.text).join("")).toBe(text);
  });

  it("row 8: an empty fence body is a valid exempt segment", () => {
    const text = "```noredact\n```\n";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: true }]);
  });

  it("row 9: a closing fence at EOF with no trailing newline still closes", () => {
    const text = "```noredact\nfoo\n```";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: true }]);
  });

  it("row 9: an unterminated opening fence at EOF is reclassified as non-exempt, including the orphan opening line", () => {
    const text = "before\n```noredact\nfoo\nno closer here";
    const segments = splitNoRedactSegments(text);
    // May be emitted as one or more adjacent non-exempt segments (any
    // pre-fence plain buffer is flushed separately from the reclassified
    // fence buffer) — what matters is that nothing is marked exempt and the
    // full text round-trips.
    expect(segments.every((s) => s.exempt === false)).toBe(true);
    expect(segments.map((s) => s.text).join("")).toBe(text);
  });

  it("row 10: no nesting — a bare fence inside a noredact block closes it early (safe direction)", () => {
    const text = "```noredact\nfoo\n```\nbar\n```\nafter";
    const segments = splitNoRedactSegments(text);
    // The first ``` (3 backticks) after "foo" closes the 3-backtick noredact
    // fence early; "bar" and the trailing bare ``` fence are then ordinary,
    // non-exempt text.
    expect(segments).toEqual([
      { text: "```noredact\nfoo\n```\n", exempt: true },
      { text: "bar\n```\nafter", exempt: false },
    ]);
  });

  it("row 11: the fence delimiter lines are included inside the exempt segment", () => {
    const text = "```noredact\nfoo\n```\n";
    const [segment] = splitNoRedactSegments(text);
    expect(segment.text.startsWith("```noredact")).toBe(true);
    expect(segment.text.endsWith("```\n")).toBe(true);
  });

  it("row 12: an inline occurrence mid-line is not a fence", () => {
    const text = "some text ```noredact``` more text";
    const segments = splitNoRedactSegments(text);
    expect(segments).toEqual([{ text, exempt: false }]);
  });
});
