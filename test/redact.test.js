// spec: openspec/specs/tool-output-redaction/spec.md
// spec: openspec/specs/user-message-redaction/spec.md
import { describe, it, expect, vi } from "vitest";
import {
  normalizeRanges,
  expandToTokenBoundaries,
  mergeIntervals,
  spliceRedactions,
  shortRuleId,
  buildAnnotation,
  scanAndRedact,
  redactSecrets,
  redactUserMessage,
  buildUserMessageAnnotation,
} from "../src/redact.js";

describe("expandToTokenBoundaries", () => {
  it("expands a range left and right to the nearest whitespace", () => {
    const text = "prefix ABCDEF12345 suffix";
    const start = text.indexOf("ABCDEF12345");
    const end = start + "ABCDEF12345".length;
    // shrink the reported range so it only partially covers the token
    const partialStart = start + 2;
    const partialEnd = end - 2;
    expect(expandToTokenBoundaries(text, partialStart, partialEnd)).toEqual([start, end]);
  });

  it("stops at a newline boundary", () => {
    const text = "line1\nSECRETVALUE\nline3";
    const start = text.indexOf("SECRETVALUE");
    const end = start + "SECRETVALUE".length;
    expect(expandToTokenBoundaries(text, start + 1, end - 1)).toEqual([start, end]);
  });

  it("does not expand past the start or end of the text", () => {
    const text = "TOKEN";
    expect(expandToTokenBoundaries(text, 0, text.length)).toEqual([0, text.length]);
  });

  it("Stops expansion at a structural delimiter in dense JSON", () => {
    // A compact, single-line JSON object with two string fields and no
    // whitespace anywhere: a finding in field "a" must stay bounded by its
    // own surrounding quotes and not swallow field "b" or the rest of the
    // document.
    const text = '{"a":"AAAAAAAAAAAAAAAAAAAAAAA","b":"BBBBBBBBBBBBBBBBBBBBBBB"}';
    const value = "A".repeat(23);
    const start = text.indexOf(value);
    const end = start + value.length;
    // shrink the reported range so it only partially covers the value
    const partialStart = start + 2;
    const partialEnd = end - 2;
    expect(expandToTokenBoundaries(text, partialStart, partialEnd)).toEqual([start, end]);
  });

  it.each([
    ['"', '"'],
    ["'", "'"],
    ["`", "`"],
    [",", ","], // comma is its own open/close pair, not a mismatched typo
    ["{", "}"],
    ["[", "]"],
  ])("stops expansion at a %s delimiter with no whitespace present", (open, close) => {
    const text = `prefix${open}SECRETVALUE${close}suffix`;
    const start = text.indexOf("SECRETVALUE");
    const end = start + "SECRETVALUE".length;
    expect(expandToTokenBoundaries(text, start + 1, end - 1)).toEqual([start, end]);
  });
});

describe("normalizeRanges", () => {
  it("drops a malformed range without throwing", () => {
    const text = "hello world";
    const messages = [
      { ruleId: "bad", range: [5, 2] }, // end < start
      { ruleId: "bad2", range: [-1, 3] }, // negative start
      { ruleId: "bad3", range: [0, 1000] }, // end beyond text length
    ];
    expect(normalizeRanges(text, messages)).toEqual([]);
  });

  it("expands a valid range to token boundaries and tags it with the rule id", () => {
    const text = "prefix ABCDEF12345 suffix";
    const innerStart = text.indexOf("ABCDEF12345") + 2;
    const innerEnd = innerStart + "ABCDEF1234".length - 2;
    const messages = [{ ruleId: "example-rule", range: [innerStart, innerEnd] }];
    const [interval] = normalizeRanges(text, messages);
    expect(interval.start).toBe(text.indexOf("ABCDEF12345"));
    expect(interval.end).toBe(text.indexOf("ABCDEF12345") + "ABCDEF12345".length);
    expect(interval.ruleIds).toEqual(new Set(["example-rule"]));
  });
});

describe("mergeIntervals", () => {
  const iv = (start, end, ...ruleIds) => ({ start, end, ruleIds: new Set(ruleIds) });

  it("merges two overlapping intervals into one", () => {
    const merged = mergeIntervals([iv(0, 10, "a"), iv(5, 15, "b")]);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toEqual({ start: 0, end: 15, ruleIds: new Set(["a", "b"]) });
  });

  it("merges two intervals that exactly touch", () => {
    const merged = mergeIntervals([iv(0, 10, "a"), iv(10, 20, "b")]);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toEqual({ start: 0, end: 20, ruleIds: new Set(["a", "b"]) });
  });

  it("keeps disjoint intervals separate", () => {
    const merged = mergeIntervals([iv(0, 5, "a"), iv(10, 15, "b")]);
    expect(merged).toHaveLength(2);
    expect(merged[0]).toEqual({ start: 0, end: 5, ruleIds: new Set(["a"]) });
    expect(merged[1]).toEqual({ start: 10, end: 15, ruleIds: new Set(["b"]) });
  });

  it("sorts unordered input before merging", () => {
    const merged = mergeIntervals([iv(10, 15, "b"), iv(0, 5, "a")]);
    expect(merged.map((m) => m.start)).toEqual([0, 10]);
  });

  it("returns an empty array for empty input", () => {
    expect(mergeIntervals([])).toEqual([]);
  });
});

describe("spliceRedactions", () => {
  const iv = (start, end, ...ruleIds) => ({ start, end, ruleIds: new Set(ruleIds) });

  it("replaces a single finding with an exact placeholder, byte-exact surrounding text", () => {
    const text = "before SECRET after";
    const start = text.indexOf("SECRET");
    const end = start + "SECRET".length;
    const result = spliceRedactions(text, [iv(start, end, "@secretlint/secretlint-rule-example")]);
    expect(result).toBe("before ***REDACTED:example*** after");
  });

  it("replaces multiple disjoint findings, preserving text between them", () => {
    const text = "AAA middle BBB";
    const result = spliceRedactions(text, [
      iv(0, 3, "@secretlint/secretlint-rule-one"),
      iv(11, 14, "@secretlint/secretlint-rule-two"),
    ]);
    expect(result).toBe("***REDACTED:one*** middle ***REDACTED:two***");
  });

  it("returns the original text unchanged when there are no intervals", () => {
    expect(spliceRedactions("unchanged text", [])).toBe("unchanged text");
  });

  it("produces exactly one placeholder for a merged multi-rule interval", () => {
    const text = "XXXXXXXXXX";
    const result = spliceRedactions(text, [
      iv(0, 10, "@secretlint/secretlint-rule-aws", "@secretlint/secretlint-rule-privatekey"),
    ]);
    expect(result).toBe("***REDACTED:aws+privatekey***");
  });
});

describe("shortRuleId", () => {
  it("strips the @secretlint/secretlint-rule- prefix", () => {
    expect(shortRuleId("@secretlint/secretlint-rule-aws")).toBe("aws");
  });

  it("falls back to the raw id when the prefix is absent", () => {
    expect(shortRuleId("some-other-rule")).toBe("some-other-rule");
  });
});

describe("buildAnnotation", () => {
  it("mentions the redaction count and deduplicated, sorted rule labels", () => {
    const annotation = buildAnnotation(2, ["aws", "privatekey", "aws"]);
    expect(annotation).toContain("2");
    expect(annotation).toContain("aws+privatekey");
  });

  it("instructs never to write a placeholder back to a file or message", () => {
    const annotation = buildAnnotation(1, ["aws"]);
    expect(annotation.toLowerCase()).toContain("never");
    expect(annotation).toContain("***REDACTED:");
  });
});

describe("scanAndRedact", () => {
  it("returns the input unchanged and never calls lint for an empty string", async () => {
    const lint = vi.fn();
    const result = await scanAndRedact("", { lint });
    expect(result).toEqual({ text: "", redactionCount: 0, ruleIds: [] });
    expect(lint).not.toHaveBeenCalled();
  });

  it("returns the input unchanged and never calls lint for a non-string value", async () => {
    const lint = vi.fn();
    const result = await scanAndRedact(undefined, { lint });
    expect(result).toEqual({ text: undefined, redactionCount: 0, ruleIds: [] });
    expect(lint).not.toHaveBeenCalled();
  });

  it("returns the redacted text with NO annotation appended when a finding is redacted", async () => {
    const text = "token: AAAAAAAAAAAAAAAAAAAA secret_value";
    const start = text.indexOf("AAAAAAAAAAAAAAAAAAAA");
    const end = start + "AAAAAAAAAAAAAAAAAAAA".length;
    const lint = vi.fn().mockResolvedValue([{ ruleId: "@secretlint/secretlint-rule-example", range: [start, end] }]);
    const result = await scanAndRedact(text, { lint });
    expect(result.text).toContain("***REDACTED:example***");
    expect(result.text).not.toContain("[opencode-redact]");
    expect(result.redactionCount).toBe(1);
    expect(result.ruleIds).toEqual(["example"]);
  });

  it("returns the original text unchanged when lint throws (fail open)", async () => {
    const lint = vi.fn().mockRejectedValue(new Error("scanner exploded"));
    const text = "aws_secret_access_key=AAAAAAAAAAAAAAAAAAAA";
    const result = await scanAndRedact(text, { lint });
    expect(result).toEqual({ text, redactionCount: 0, ruleIds: [] });
  });
});

describe("redactSecrets", () => {
  it("is scanAndRedact plus the tool-output annotation appended after a redaction", async () => {
    const text = "token: AAAAAAAAAAAAAAAAAAAA secret_value";
    const start = text.indexOf("AAAAAAAAAAAAAAAAAAAA");
    const end = start + "AAAAAAAAAAAAAAAAAAAA".length;
    const lint = vi.fn().mockResolvedValue([{ ruleId: "@secretlint/secretlint-rule-example", range: [start, end] }]);
    const scanned = await scanAndRedact(text, { lint });
    const redacted = await redactSecrets(text, { lint });
    expect(redacted.text).toBe(`${scanned.text}\n\n${buildAnnotation(scanned.redactionCount, scanned.ruleIds)}`);
    expect(redacted.redactionCount).toBe(scanned.redactionCount);
    expect(redacted.ruleIds).toEqual(scanned.ruleIds);
  });


  it("returns the input unchanged and never calls lint for an empty string", async () => {
    const lint = vi.fn();
    const result = await redactSecrets("", { lint });
    expect(result).toEqual({ text: "", redactionCount: 0, ruleIds: [] });
    expect(lint).not.toHaveBeenCalled();
  });

  it("returns the input unchanged and never calls lint for a non-string value", async () => {
    const lint = vi.fn();
    const result = await redactSecrets(undefined, { lint });
    expect(result).toEqual({ text: undefined, redactionCount: 0, ruleIds: [] });
    expect(lint).not.toHaveBeenCalled();
  });

  it("calls lint even for clean, anchor-free text (the anchor prescreen is the injected lint's own responsibility, not scanAndRedact's)", async () => {
    const lint = vi.fn().mockResolvedValue([]);
    const text = "the quick brown fox jumps over the lazy dog";
    const result = await redactSecrets(text, { lint });
    expect(result).toEqual({ text, redactionCount: 0, ruleIds: [] });
    expect(lint).toHaveBeenCalledWith(text);
  });

  it("returns the original text unchanged when lint throws (fail open)", async () => {
    const lint = vi.fn().mockRejectedValue(new Error("scanner exploded"));
    const text = "aws_secret_access_key=ZQ7mK4pXvB2nJ8wR5tL9cF3hD6yG1sA0uEZQ7mK4";
    const result = await redactSecrets(text, { lint });
    expect(result).toEqual({ text, redactionCount: 0, ruleIds: [] });
  });

  it("redacts text and appends an annotation when lint reports a finding", async () => {
    const text = "token: AAAAAAAAAAAAAAAAAAAA secret_value";
    const start = text.indexOf("AAAAAAAAAAAAAAAAAAAA");
    const end = start + "AAAAAAAAAAAAAAAAAAAA".length;
    const lint = vi.fn().mockResolvedValue([
      { ruleId: "@secretlint/secretlint-rule-example", range: [start, end] },
    ]);
    const result = await redactSecrets(text, { lint });
    expect(result.text).toContain("***REDACTED:example***");
    expect(result.text).toContain("[opencode-redact]");
    expect(result.redactionCount).toBe(1);
    expect(result.ruleIds).toEqual(["example"]);
  });

  it("appends the annotation exactly once, after every placeholder, even with multiple findings", async () => {
    const text = "secret_one=AAAAAAAAAA middle secret_two=BBBBBBBBBB";
    const firstStart = text.indexOf("AAAAAAAAAA");
    const secondStart = text.indexOf("BBBBBBBBBB");
    const lint = vi.fn().mockResolvedValue([
      { ruleId: "@secretlint/secretlint-rule-one", range: [firstStart, firstStart + 10] },
      { ruleId: "@secretlint/secretlint-rule-two", range: [secondStart, secondStart + 10] },
    ]);
    const result = await redactSecrets(text, { lint });
    const annotationMatches = result.text.match(/\[opencode-redact\]/g) ?? [];
    expect(annotationMatches).toHaveLength(1);
    const annotationIndex = result.text.indexOf("[opencode-redact]");
    const bodyBeforeAnnotation = result.text.slice(0, annotationIndex);
    const lastPlaceholderInBody = bodyBeforeAnnotation.lastIndexOf("***REDACTED:");
    expect(lastPlaceholderInBody).toBeGreaterThanOrEqual(0);
    expect(annotationIndex).toBeGreaterThan(lastPlaceholderInBody);
  });

  it("redacts two non-overlapping findings end-to-end through the orchestrator", async () => {
    const text = "secret_one=AAAAAAAAAA middle secret_two=BBBBBBBBBB";
    const firstStart = text.indexOf("AAAAAAAAAA");
    const firstEnd = firstStart + "AAAAAAAAAA".length;
    const secondStart = text.indexOf("BBBBBBBBBB");
    const secondEnd = secondStart + "BBBBBBBBBB".length;
    const lint = vi.fn().mockResolvedValue([
      { ruleId: "@secretlint/secretlint-rule-one", range: [firstStart, firstEnd] },
      { ruleId: "@secretlint/secretlint-rule-two", range: [secondStart, secondEnd] },
    ]);
    const result = await redactSecrets(text, { lint });
    expect(result.text).toContain("***REDACTED:one*** middle ***REDACTED:two***");
    expect(result.redactionCount).toBe(2);
    expect(result.ruleIds.sort()).toEqual(["one", "two"]);
  });

  it("merges two overlapping findings into a single placeholder end-to-end through the orchestrator", async () => {
    const text = "secret_value=XXXXXXXXXXXXXXXXXXXX";
    const tokenStart = text.indexOf("XXXXXXXXXXXXXXXXXXXX");
    const lint = vi.fn().mockResolvedValue([
      { ruleId: "@secretlint/secretlint-rule-aws", range: [tokenStart, tokenStart + 12] },
      { ruleId: "@secretlint/secretlint-rule-privatekey", range: [tokenStart + 8, tokenStart + 20] },
    ]);
    const result = await redactSecrets(text, { lint });
    expect(result.text).toContain("***REDACTED:aws+privatekey***");
    expect(result.redactionCount).toBe(1);
  });

  it("returns the original text unchanged when the scanner rejects with a timeout-shaped error", async () => {
    const text = "aws_secret_access_key=ZQ7mK4pXvB2nJ8wR5tL9cF3hD6yG1sA0uEZQ7mK4";
    const lint = vi.fn().mockRejectedValue(new Error("secretlint scan timed out after 3000ms"));
    const result = await redactSecrets(text, { lint });
    expect(result).toEqual({ text, redactionCount: 0, ruleIds: [] });
  });

  it("does not append an annotation when lint reports no findings", async () => {
    const text = "token: AAAAAAAAAAAAAAAAAAAA secret_value";
    const lint = vi.fn().mockResolvedValue([]);
    const result = await redactSecrets(text, { lint });
    expect(result).toEqual({ text, redactionCount: 0, ruleIds: [] });
  });
});

describe("redactUserMessage", () => {
  it("returns the input unchanged and never calls lint for an empty string", async () => {
    const lint = vi.fn();
    const result = await redactUserMessage("", { lint });
    expect(result).toEqual({ text: "", redactionCount: 0, ruleIds: [] });
    expect(lint).not.toHaveBeenCalled();
  });

  it("returns the input unchanged and never calls lint for a non-string value", async () => {
    const lint = vi.fn();
    const result = await redactUserMessage(undefined, { lint });
    expect(result).toEqual({ text: undefined, redactionCount: 0, ruleIds: [] });
    expect(lint).not.toHaveBeenCalled();
  });

  it("calls lint even for clean, anchor-free text (the anchor prescreen is the injected lint's own responsibility, not redactUserMessage's)", async () => {
    const lint = vi.fn().mockResolvedValue([]);
    const text = "the quick brown fox jumps over the lazy dog";
    const result = await redactUserMessage(text, { lint });
    expect(result).toEqual({ text, redactionCount: 0, ruleIds: [] });
    expect(lint).toHaveBeenCalledWith(text);
  });

  it("redacts a secret found outside any fence, appending no annotation itself", async () => {
    const text = "token: AAAAAAAAAAAAAAAAAAAA secret_value";
    const start = text.indexOf("AAAAAAAAAAAAAAAAAAAA");
    const end = start + "AAAAAAAAAAAAAAAAAAAA".length;
    const lint = vi.fn().mockResolvedValue([{ ruleId: "@secretlint/secretlint-rule-example", range: [start, end] }]);
    const result = await redactUserMessage(text, { lint });
    expect(result.text).toContain("***REDACTED:example***");
    expect(result.text).not.toContain("[opencode-redact]");
    expect(result.redactionCount).toBe(1);
    expect(result.ruleIds).toEqual(["example"]);
  });

  it("leaves a noredact-fenced secret completely untouched, proving the exemption works (checksum example)", async () => {
    // A checksum that would otherwise trip a rule's anchor if scanned; wrapping it
    // in a noredact fence must leave it byte-identical, and lint must never be
    // called with the fenced segment's content, regardless of the surrounding
    // (non-fenced) text's own anchor status.
    const checksum = "aws_secret_access_key=AAAAAAAAAAAAAAAAAAAA";
    const text = `Here is a checksum:\n\`\`\`noredact\n${checksum}\n\`\`\`\nthanks!`;
    const lint = vi.fn().mockResolvedValue([]);
    const result = await redactUserMessage(text, { lint });
    expect(result.text).toBe(text);
    expect(result.text).toContain(checksum);
    expect(result.redactionCount).toBe(0);
    expect(result.ruleIds).toEqual([]);
    // lint is called for the surrounding non-fenced segments (prescreening is
    // no longer redactUserMessage's own responsibility — see design.md D2),
    // but never with any text containing the fenced checksum.
    for (const [callText] of lint.mock.calls) {
      expect(callText).not.toContain(checksum);
    }
  });

  it("redacts a secret outside the fence while leaving the fenced segment untouched, in the same message", async () => {
    const secretText = "aws_secret_access_key=AAAAAAAAAAAAAAAAAAAA";
    const fencedChecksum = "sha256:deadbeefsecretchecksum";
    const text = `${secretText}\n\`\`\`noredact\n${fencedChecksum}\n\`\`\`\n`;
    const start = text.indexOf("AAAAAAAAAAAAAAAAAAAA");
    const end = start + "AAAAAAAAAAAAAAAAAAAA".length;
    const lint = vi.fn().mockImplementation(async (segmentText) => {
      if (segmentText.includes(fencedChecksum)) {
        throw new Error("lint must never be called on an exempt segment");
      }
      return [{ ruleId: "@secretlint/secretlint-rule-aws", range: [start, end] }];
    });
    const result = await redactUserMessage(text, { lint });
    expect(result.text).toContain("***REDACTED:aws***");
    expect(result.text).toContain(fencedChecksum);
    expect(result.redactionCount).toBe(1);
    expect(result.ruleIds).toEqual(["aws"]);
  });

  it("sums redactionCount and unions+sorts ruleIds across multiple non-exempt segments", async () => {
    const text = "secret_one=AAAAAAAAAA\n```noredact\nsecret_untouched=BBBBBBBBBB\n```\nsecret_two=CCCCCCCCCC";
    const lint = vi.fn().mockImplementation(async (segmentText) => {
      const messages = [];
      if (segmentText.includes("AAAAAAAAAA")) {
        messages.push({
          ruleId: "@secretlint/secretlint-rule-two",
          range: [segmentText.indexOf("AAAAAAAAAA"), segmentText.indexOf("AAAAAAAAAA") + 10],
        });
      }
      if (segmentText.includes("CCCCCCCCCC")) {
        messages.push({
          ruleId: "@secretlint/secretlint-rule-one",
          range: [segmentText.indexOf("CCCCCCCCCC"), segmentText.indexOf("CCCCCCCCCC") + 10],
        });
      }
      return messages;
    });
    const result = await redactUserMessage(text, { lint });
    expect(result.redactionCount).toBe(2);
    expect(result.ruleIds).toEqual(["one", "two"]);
    expect(result.text).toContain("BBBBBBBBBB"); // exempt segment untouched
  });

  it("returns the original text unchanged when lint throws for a non-exempt segment (fail open)", async () => {
    const text = "aws_secret_access_key=AAAAAAAAAAAAAAAAAAAA";
    const lint = vi.fn().mockRejectedValue(new Error("scanner exploded"));
    const result = await redactUserMessage(text, { lint });
    expect(result).toEqual({ text, redactionCount: 0, ruleIds: [] });
  });
});

describe("buildUserMessageAnnotation", () => {
  it("mentions the redaction count and deduplicated, sorted rule labels", () => {
    const annotation = buildUserMessageAnnotation(2, ["aws", "privatekey", "aws"]);
    expect(annotation).toContain("2");
    expect(annotation).toContain("aws+privatekey");
  });

  it("instructs never to write a placeholder back to a file or message, and not to reconstruct the value", () => {
    const annotation = buildUserMessageAnnotation(1, ["aws"]);
    expect(annotation.toLowerCase()).toContain("never");
    expect(annotation.toLowerCase()).toContain("reconstruct");
    expect(annotation).toContain("***REDACTED:");
  });

  it("makes no mention of the noredact fence or any exemption mechanism", () => {
    const annotation = buildUserMessageAnnotation(1, ["aws"]);
    expect(annotation.toLowerCase()).not.toContain("noredact");
    expect(annotation.toLowerCase()).not.toContain("fence");
  });

  it("differs from the tool-output annotation (does not tell the model to ask the user for the value)", () => {
    const annotation = buildUserMessageAnnotation(1, ["aws"]);
    expect(annotation.toLowerCase()).not.toContain("ask the user");
  });
});
