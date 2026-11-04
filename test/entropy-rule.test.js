// spec: openspec/specs/high-entropy-secret-detection/spec.md
//
// Tests for the pure entropy-detection helpers and the secretlint rule
// module they back. Fixture values mirror design.md D9 exactly: every
// fixture is a uniform-multiset construction with an exact, hand-checkable
// Shannon entropy (order-independent, so characters are scrambled to look
// like credentials without changing the value).

import { describe, it, expect } from "vitest";
import {
  shannonEntropy,
  findCandidateRuns,
  classifyRun,
  isAllowlistedRun,
  findJwtSpans,
  findUrlSpans,
  findPathSpans,
  findHighEntropyFindings,
  findPasswordCandidateRuns,
  hasLetterCaseMix,
  hasLongClassRun,
  creator,
} from "../src/entropy-rule.js";
import { ENTROPY_FIXTURES, SHORT_PASSWORD_FIXTURES, PATH_FIXTURES } from "./entropy-fixtures.js";
import { createSecretlintConfig, createCompositeLinter } from "../src/secretlint.js";
import { RULE_FIXTURES } from "./fixtures.js";

const LOG2_36 = Math.log2(36); // 5.169925001442312
const LOG2_26 = Math.log2(26); // 4.700439718141092
const LOG2_16 = Math.log2(16); // 4.0
const LOG2_4 = Math.log2(4); // 2.0
const LOG2_8 = Math.log2(8); // 3.0

describe("entropy exemption boundaries", () => {
  const secret = Array.from({ length: 36 }, (_, i) => i.toString(36)).join("");
  const short = SHORT_PASSWORD_FIXTURES.find((fixture) => fixture.expectFinding).content;

  it("Preserves integers decimals and scientific notation", () => {
    for (const number of [
      "01234567890123456789", "-98765432109876543210", "+98765432109876543210", "01234567890123456789.98765432109876543210",
      "-.01234567890123456789", "+01234567890123456789.", "01234567890123456789e+98765432109876543210", "-01234567890123456789.5E-98765432109876543210",
    ]) {
      for (const text of [number, `value=${number}`, `value: ${number}`, `[${number}]`, `(${number}),`]) {
        expect(findHighEntropyFindings(text), text).toEqual([]);
      }
    }
  });

  it("Does not exempt numeric fragments inside credentials", () => {
    for (const text of [
      `0123456789${secret}`, `${secret}0123456789`, `0123456789.${secret}`,
      `0123456789e+${secret}`, `01234567890123456789.98765432109876543210.12345678901234567890`, `0123456789=${secret}`,
    ]) {
      expect(findHighEntropyFindings(text).length, text).toBeGreaterThan(0);
    }
  });

  it("Detects secrets adjacent to exempt spans", () => {
    for (const token of [secret, short]) {
      for (const span of [`https://example.invalid/${token}`, `/${token}`, `C:\\${token}`]) {
        for (const [open, close] of [["`", "`"], ["[", "]"], ["{", "}"], ["(", ")"], ["<", ">"], ['"', '"'], ["'", "'"], [" ", " "]]) {
          const text = `${open}${span}${close}${token}`;
          expect(findHighEntropyFindings(text), text).toEqual([
            { start: text.length - token.length, end: text.length },
          ]);
        }
      }
    }
  });

  it("Detects outside fragments of candidates crossing exemption boundaries", () => {
    for (const token of [secret, short]) {
      const text = `${token}=https://example.invalid/${token}`;
      // '=' belongs to the generic alphabet, but not the short-password alphabet.
      const outside = token === secret ? `${token}=` : token;
      expect(findHighEntropyFindings(text)).toEqual([{ start: 0, end: outside.length }]);
    }
  });

  it("Keeps JWT signature detection active inside exempt spans", () => {
    const jwt = `eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.${secret}`; // pragma: allowlist secret -- unsigned synthetic claims and generated signature
    for (const text of [`https://example.invalid/${jwt}`, `/tmp/${jwt}`, `C:\\tmp\\${jwt}`]) {
      const start = text.indexOf(secret);
      expect(findHighEntropyFindings(text)).toEqual([{ start, end: start + secret.length }]);
    }
  });

  it("Keeps explicit credential detection active inside exempt spans", async () => {
    const lint = createCompositeLinter(await createSecretlintConfig());
    const fixture = RULE_FIXTURES.find((entry) => entry.rule === "basicauth");
    const messages = await lint(fixture.content, { ext: fixture.ext });
    expect(messages.some((message) => message.messageId === fixture.messageId)).toBe(true);
  });
});

describe("shannonEntropy", () => {
  it("is 0 for an empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("is 0 for a string of one repeated character", () => {
    expect(shannonEntropy("aaaaaaaaaa")).toBe(0);
  });

  it("computes log2(36) for 36 distinct base64-alphabet symbols, each occurring once", () => {
    const distinct = "0123456789abcdefghijklmnopqrstuvwxyz"; // 10 + 26 = 36 distinct chars
    expect(distinct).toHaveLength(36);
    expect(shannonEntropy(distinct)).toBeCloseTo(LOG2_36, 9);
  });

  it("computes log2(26) for the 26 lowercase letters, each occurring once", () => {
    const distinct = "abcdefghijklmnopqrstuvwxyz";
    expect(shannonEntropy(distinct)).toBeCloseTo(LOG2_26, 9);
  });

  it("computes log2(16) for three repetitions of 16 distinct hex symbols", () => {
    const text = "0123456789abcdef".repeat(3);
    expect(shannonEntropy(text)).toBeCloseTo(LOG2_16, 9);
  });

  it("computes log2(4) for a repeated 4-symbol pattern", () => {
    const text = "0123".repeat(11);
    expect(shannonEntropy(text)).toBeCloseTo(LOG2_4, 9);
  });

  it("computes log2(8) exactly for a repeated 8-symbol pattern (the hex boundary fixture)", () => {
    const text = "01234567".repeat(6);
    expect(shannonEntropy(text)).toBeCloseTo(LOG2_8, 9);
  });
});

describe("findCandidateRuns", () => {
  it("finds a single run spanning the whole input when it is all one charset", () => {
    const text = "aGVsbG8gd29ybGQ";
    expect(findCandidateRuns(text)).toEqual([{ start: 0, end: text.length, text }]);
  });

  it("splits on characters outside the run charset", () => {
    const text = '{"apiKey":"a8Fk9Zx"}';
    const runs = findCandidateRuns(text);
    expect(runs.map((r) => r.text)).toEqual(["apiKey", "a8Fk9Zx"]);
  });

  it("returns disjoint runs that never overlap", () => {
    const text = "foo.bar.baz qux-quux";
    const runs = findCandidateRuns(text);
    for (let i = 1; i < runs.length; i += 1) {
      expect(runs[i].start).toBeGreaterThanOrEqual(runs[i - 1].end);
    }
  });

  it("returns an empty array for text with no qualifying characters", () => {
    expect(findCandidateRuns("... :: {} !!")).toEqual([]);
  });
});

describe("classifyRun", () => {
  it("classifies an all-hex run as hex (hex-first ordering)", () => {
    expect(classifyRun("0123456789abcdef")).toEqual({ charset: "hex", threshold: 3.0, minLength: 9 });
  });

  it("classifies an all-uppercase-hex run as hex", () => {
    expect(classifyRun("0123456789ABCDEF")).toMatchObject({ charset: "hex" });
  });

  it("classifies a base64-shaped run containing a non-hex letter as base64", () => {
    expect(classifyRun("aGVsbG8gd29ybGQ")).toEqual({ charset: "base64", threshold: 4.5, minLength: 23 });
  });

  it("returns null for a run containing characters outside both alphabets", () => {
    expect(classifyRun("hello world!")).toBeNull();
  });
});

describe("isAllowlistedRun", () => {
  it("exempts a lowercase 7-character abbreviated git commit id", () => {
    expect(isAllowlistedRun("bab179f")).toBe(true);
  });

  it("exempts a lowercase 12-character abbreviated git commit id", () => {
    expect(isAllowlistedRun("bab179f39dd1")).toBe(true);
  });

  it("exempts an uppercase 40-character hash digest", () => {
    expect(isAllowlistedRun("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")).toBe(true);
  });

  it("exempts a lowercase 40-character hash digest (SHA-1 of the empty input)", () => {
    expect(isAllowlistedRun("da39a3ee5e6b4b0d3255bfef95601890afd80709")).toBe(true);
  });

  it("does not exempt a mixed-case 40-character hex run of the same length", () => {
    // identical characters to the exempt SHA-1 fixture but with a, b, c
    // upper-cased -- same length, same entropy, only case differs.
    const mixedCase = "dA39A3ee5e6b4b0d3255bfef95601890afd80709";
    expect(isAllowlistedRun(mixedCase)).toBe(false);
  });

  it("does not exempt a mixed-case 32-character hex run (case-uniformity pair)", () => {
    const uniform32 = "0123456789abcdef0123456789abcdef".slice(0, 32);
    expect(uniform32).toHaveLength(32);
    expect(isAllowlistedRun(uniform32)).toBe(true);
    const mixedCase32 = "0123456789ABCdef0123456789abcdef".slice(0, 32);
    expect(mixedCase32).toHaveLength(32);
    expect(isAllowlistedRun(mixedCase32)).toBe(false);
  });

  it("exempts a canonically-formatted UUID regardless of case", () => {
    expect(isAllowlistedRun("550e8400-e29b-41d4-a716-446655440000")).toBe(true);
    expect(isAllowlistedRun("550E8400-E29B-41D4-A716-446655440000")).toBe(true);
  });

  it("does not exempt a run merely containing a UUID shape with extra trailing content", () => {
    expect(isAllowlistedRun("550e8400-e29b-41d4-a716-446655440000-REALSECRET")).toBe(false);
  });

  it("exempts an opencode session identifier", () => {
    expect(isAllowlistedRun("ses_4Qe7Lk2Vb9Xr1Tn8Hc3Mz6Wd0J")).toBe(true); // pragma: allowlist secret
  });

  it.each(["ses", "msg", "prt", "per", "psv", "frm", "wrk", "evt", "sh", "cred", "pty", "con"])(
    "exempts an opencode identifier with the %s_ prefix",
    (prefix) => {
      expect(isAllowlistedRun(`${prefix}_4Qe7Lk2Vb9Xr1Tn8Hc3Mz6Wd0J`)).toBe(true);
    },
  );

  it("does not exempt an opencode identifier with a secret glued to it", () => {
    expect(isAllowlistedRun("ses_4Qe7Lk2Vb9Xr1Tn8Hc3Mz6Wd0J-REALSECRET")).toBe(false); // pragma: allowlist secret
    expect(isAllowlistedRun("REALSECRET-ses_4Qe7Lk2Vb9Xr1Tn8Hc3Mz6Wd0J")).toBe(false); // pragma: allowlist secret
  });

  it("does not exempt an opencode-prefixed run with a suffix of the wrong length", () => {
    expect(isAllowlistedRun("ses_4Qe7Lk2Vb9Xr1Tn8Hc3Mz6Wd0")).toBe(false); // pragma: allowlist secret
    expect(isAllowlistedRun("ses_4Qe7Lk2Vb9Xr1Tn8Hc3Mz6Wd0Jx")).toBe(false); // pragma: allowlist secret
  });

  it("does not exempt an unknown prefix with a 26-character base-62 suffix", () => {
    expect(isAllowlistedRun("foo_4Qe7Lk2Vb9Xr1Tn8Hc3Mz6Wd0J")).toBe(false); // pragma: allowlist secret
  });

  it("exempts a Subresource Integrity hash", () => {
    expect(isAllowlistedRun("sha512-2eDaqheYQiOtbY2wR2Ck2AiwPRXJhrZ0Nc/l5MMjhqZ1PbNr2gDkG9pW+GYA/JzOTkyCcz4LgN")).toBe(
      true,
    );
  });

  it("does not exempt a bare padded base64 digest with no SRI prefix", () => {
    expect(isAllowlistedRun("2eDaqheYQiOtbY2wR2Ck2AiwPRXJhrZ0Nc/l5MMjhqQ==")).toBe(false);
  });

  it("does not exempt an unrelated high-entropy run", () => {
    expect(isAllowlistedRun("0123456789abcdefghijklmnopqrstuvwxyz")).toBe(false);
  });
});

describe("findJwtSpans", () => {
  const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
  const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";

  it("finds a signed JWT and reports the signature's exact range", () => {
    const signature = "aaaaaaaaaaaaaaaaaaaaaaaa"; // 24 chars
    const text = `${header}.${payload}.${signature}`;
    const spans = findJwtSpans(text);
    expect(spans).toHaveLength(1);
    const [span] = spans;
    expect(span.start).toBe(0);
    expect(span.end).toBe(text.length);
    expect(span.signatureRange).toEqual({
      start: header.length + 1 + payload.length + 1,
      end: text.length,
    });
    expect(text.slice(span.signatureRange.start, span.signatureRange.end)).toBe(signature);
  });

  it("reports no signature range for an unsigned (alg: none) JWT", () => {
    const text = `${header}.${payload}.`;
    const spans = findJwtSpans(text);
    expect(spans).toHaveLength(1);
    expect(spans[0].signatureRange).toBeNull();
  });

  it("finds no JWT span in ordinary text or a bare three-part dotted string without the eyJ prefix", () => {
    expect(findJwtSpans("1.2.3")).toEqual([]);
    expect(findJwtSpans("just some ordinary prose.")).toEqual([]);
  });
});

describe("findHighEntropyFindings (integration of the pure helpers)", () => {
  it("reports the base64-positive fixture (36 distinct symbols)", () => {
    const fixture = "0123456789abcdefghijklmnopqrstuvwxyz";
    const text = `value: ${fixture} end`;
    const findings = findHighEntropyFindings(text);
    expect(findings).toHaveLength(1);
    const [finding] = findings;
    expect(text.slice(finding.start, finding.end)).toBe(fixture);
  });

  it("does not report the hex boundary fixture (exactly 3.0 bits/char)", () => {
    const text = `value=${"01234567".repeat(6)} end`;
    expect(findHighEntropyFindings(text)).toEqual([]);
  });

  it("does not report the hex negative fixture (log2(4), scored but under threshold)", () => {
    const text = `value=${"0123".repeat(11)} end`;
    expect(findHighEntropyFindings(text)).toEqual([]);
  });

  it("does not report a below-floor-length base64 run even if it were hypothetically high-entropy", () => {
    const text = "value=abcdefghijklmnopqrstu end"; // 21 chars, below the 23-char floor
    expect(findHighEntropyFindings(text)).toEqual([]);
  });

  it("does not report an allowlisted git SHA despite its entropy exceeding the hex threshold", () => {
    const text = "commit da39a3ee5e6b4b0d3255bfef95601890afd80709 done";
    expect(findHighEntropyFindings(text)).toEqual([]);
  });

  it("reports exactly one finding for a signed JWT, matching only the signature range", () => {
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";
    const signature = "aaaaaaaaaaaaaaaaaaaaaaaa";
    const text = `Authorization: Bearer ${header}.${payload}.${signature}`;
    const findings = findHighEntropyFindings(text);
    expect(findings).toHaveLength(1);
    expect(text.slice(findings[0].start, findings[0].end)).toBe(signature);
  });

  it("reports nothing for an unsigned JWT (no fallback scoring of header/payload)", () => {
    const header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
    const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";
    const text = `${header}.${payload}.`;
    expect(findHighEntropyFindings(text)).toEqual([]);
  });
});

describe("ENTROPY_FIXTURES (D9 verified fixtures)", () => {
  it("matches expectFinding for every fixture via findHighEntropyFindings", () => {
    for (const fixture of ENTROPY_FIXTURES) {
      const findings = findHighEntropyFindings(fixture.content);
      expect(findings.length > 0, `fixture '${fixture.name}' expected finding=${fixture.expectFinding}`).toBe(
        fixture.expectFinding,
      );
    }
  });
});

describe("entropy rule module (secretlint rule creator shape)", () => {
  it("has the expected meta shape", () => {
    expect(creator.meta.type).toBe("scanner");
    expect(creator.meta.supportedContentTypes).toEqual(["text"]);
  });

  it("reports via context.report with a constant message and no interpolated data", () => {
    const reports = [];
    const fakeContext = {
      createTranslator: (messages) => (messageId) => ({
        message: messages[messageId].en(),
        messageId,
        data: undefined,
      }),
      report(descriptor) {
        reports.push(descriptor);
      },
    };
    const handler = creator.create(fakeContext, {});
    const fixture = "0123456789abcdefghijklmnopqrstuvwxyz";
    const content = `value: ${fixture}`;
    handler.file({ content, filePath: "/dev/null/x.txt", ext: ".txt", contentType: "text" });
    expect(reports).toHaveLength(1);
    expect(reports[0].message.data).toBeUndefined();
    expect(typeof reports[0].message.message).toBe("string");
    const [start, end] = reports[0].range;
    expect(content.slice(start, end)).toBe(fixture);
  });
});

describe("findPasswordCandidateRuns", () => {
  it("finds a single run spanning the whole input when it is all password-shaped charset", () => {
    const text = "aB3!cD7#eF2$gH";
    expect(findPasswordCandidateRuns(text)).toEqual([{ start: 0, end: text.length, text }]);
  });

  it("splits on characters outside the password-shaped charset (e.g. '/')", () => {
    const text = "sha256-XY/aB1cD2eF3gH4iJ/ZW==";
    const runs = findPasswordCandidateRuns(text);
    expect(runs.map((r) => r.text)).toEqual(["sha256-XY", "aB1cD2eF3gH4iJ", "ZW"]);
  });

  it("is independent of the existing base64/hex tokenization pass", () => {
    const text = "aB3!cD7#eF2$gH";
    expect(findCandidateRuns(text).map((r) => r.text)).not.toEqual(findPasswordCandidateRuns(text).map((r) => r.text));
  });
});

describe("hasLetterCaseMix", () => {
  it("returns true when both a lowercase and an uppercase letter are present", () => {
    expect(hasLetterCaseMix("aB1!cD2#eF3$gH4%iJ5^kL")).toBe(true);
  });

  it("returns false when only lowercase letters are present", () => {
    expect(hasLetterCaseMix("a1!b2#c3$d4%e5^f")).toBe(false);
  });

  it("returns false when only uppercase letters are present", () => {
    expect(hasLetterCaseMix("A1!B2#C3$D4%E5^F")).toBe(false);
  });
});

describe("hasLongClassRun", () => {
  it("returns false for a run with no 4+ same-class run (a genuine password shape)", () => {
    expect(hasLongClassRun("aB1!cD2#eF3$gH4%iJ5^kL")).toBe(false);
  });

  it("returns true for a run containing a 4+ consecutive lowercase run", () => {
    expect(hasLongClassRun("rightHandSymbols")).toBe(true);
  });

  it("returns true for a run containing a 4+ consecutive uppercase run", () => {
    expect(hasLongClassRun("aBCDEfg1")).toBe(true);
  });

  it("returns true for a run containing a 4+ consecutive digit run", () => {
    expect(hasLongClassRun("aB1234cD")).toBe(true);
  });

  it("returns true for a run containing a 4+ consecutive symbol run", () => {
    expect(hasLongClassRun("aB!@#$cD")).toBe(true);
  });
});

describe("findHighEntropyFindings — short password-shaped path", () => {
  it("flags a password-shaped substring meeting every condition (14-character fixture at the floor)", () => {
    const fixture = "aB3!cD7#eF2$gH";
    expect(fixture).toHaveLength(14);
    const findings = findHighEntropyFindings(fixture);
    expect(findings).toEqual([{ start: 0, end: 14 }]);
  });

  it("flags a password-shaped substring meeting every condition (22-character fixture at the ceiling)", () => {
    const fixture = "aB1!cD2#eF3$gH4%iJ5^kL";
    expect(fixture).toHaveLength(22);
    expect(findHighEntropyFindings(fixture)).toEqual([{ start: 0, end: 22 }]);
  });

  it("symbols are optional, not required", () => {
    const fixture = "aB1mcD3NeF5mgH7NiJkL";
    expect(fixture).toHaveLength(20);
    expect(findHighEntropyFindings(fixture)).toEqual([{ start: 0, end: 20 }]);
  });

  it("does not flag a substring below the 14-character floor", () => {
    const fixture = "aB3!cD7#eF2$g";
    expect(fixture).toHaveLength(13);
    expect(findHighEntropyFindings(fixture)).toEqual([]);
  });

  it("does not flag a substring at or below the entropy threshold (pins > not >=)", () => {
    const fixture = "aBc3!DeF7#gH2$aB";
    expect(fixture).toHaveLength(16);
    expect(shannonEntropy(fixture)).toBeCloseTo(3.75, 9);
    expect(findHighEntropyFindings(fixture)).toEqual([]);
  });

  it("does not flag a low-entropy repeated-pattern fixture even at floor-clearing length", () => {
    const fixture = "Ab1!".repeat(4);
    expect(fixture).toHaveLength(16);
    expect(findHighEntropyFindings(fixture)).toEqual([]);
  });

  it("does not flag a substring missing a required letter case", () => {
    const fixture = "a1!b2#c3$d4%e5^f";
    expect(fixture).toHaveLength(16);
    expect(shannonEntropy(fixture)).toBeCloseTo(4.0, 9);
    expect(findHighEntropyFindings(fixture)).toEqual([]);
  });

  it("reports the case-mix twin of the above fixture (identical length and entropy; case mix is the only discriminator)", () => {
    const fixture = "A1!b2#c3$d4%e5^f";
    expect(fixture).toHaveLength(16);
    expect(shannonEntropy(fixture)).toBeCloseTo(4.0, 9);
    expect(findHighEntropyFindings(fixture)).toEqual([{ start: 0, end: 16 }]);
  });

  it("does not flag a substring with a same-class character run of four or more", () => {
    const fixture = "acegikBDFHJL12345!#$%^";
    expect(fixture).toHaveLength(22);
    expect(shannonEntropy(fixture)).toBeCloseTo(4.4594316186, 9);
    expect(hasLongClassRun(fixture)).toBe(true);
    expect(findHighEntropyFindings(fixture)).toEqual([]);
  });

  it("does not report a real dependency-derived identifier rejected by the entropy threshold alone (regression guard)", () => {
    const fixture = "getFileUrlFromFullPath";
    expect(fixture).toHaveLength(22);
    expect(hasLetterCaseMix(fixture)).toBe(true);
    expect(hasLongClassRun(fixture)).toBe(false);
    expect(shannonEntropy(fixture)).toBeLessThan(3.75);
    expect(findHighEntropyFindings(fixture)).toEqual([]);
  });

  it("does not report a real dependency-derived identifier rejected by the class-run cap alone, despite clearing the entropy threshold (regression guard)", () => {
    const fixture = "rightHandSymbols";
    expect(fixture).toHaveLength(16);
    expect(shannonEntropy(fixture)).toBeGreaterThan(3.75);
    expect(hasLongClassRun(fixture)).toBe(true);
    expect(findHighEntropyFindings(fixture)).toEqual([]);
  });

  it("does not independently report a real base64 fixture whose entropy is under threshold", () => {
    const fixture = "aGVsbG8gd29ybGQ";
    expect(fixture).toHaveLength(15);
    expect(findHighEntropyFindings(fixture)).toEqual([]);
  });

  it("does not independently report a fragment of an allowlisted Subresource Integrity hash", () => {
    const text = "sha256-XY/aB1cD2eF3gH4iJ/ZW==";
    expect(findHighEntropyFindings(text)).toEqual([]);
  });

  it("does not independently report a fragment of a JWT header or payload segment", () => {
    // header/payload segments are base64url and may satisfy the password
    // path's charset/length/case-mix/run-cap conditions; the short path
    // must still defer entirely to the JWT pre-pass.
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";
    const signature = "aaaaaaaaaaaaaaaaaaaaaaaa";
    const text = `${header}.${payload}.${signature}`;
    const findings = findHighEntropyFindings(text);
    // Exactly one finding: the JWT signature. No independent password-path
    // finding inside the header or payload segments.
    expect(findings).toHaveLength(1);
    expect(text.slice(findings[0].start, findings[0].end)).toBe(signature);
  });

  it("does not double-report identical ranges when both the existing hex path and the short password path independently score the same run", () => {
    // 16 distinct hex-alphabet characters (0-9a-fA-F), all-distinct so
    // H = log2(16) = 4.0 -- clears the EXISTING hex path (threshold 3.0,
    // min length 9) AND the new password path (threshold 3.75, length
    // 14-22, case-mix, no long run) independently. The two tokenization
    // passes are deliberately unaware of each other; this fixture proves
    // findHighEntropyFindings itself de-duplicates the resulting identical
    // range rather than relying on mergeIntervals downstream to absorb it.
    const fixture = "0aA1bB2cC3dD4eE5";
    expect(fixture).toHaveLength(16);
    expect(shannonEntropy(fixture)).toBeCloseTo(4.0, 9);
    const findings = findHighEntropyFindings(fixture);
    expect(findings).toEqual([{ start: 0, end: 16 }]);
  });
});

describe("SHORT_PASSWORD_FIXTURES (design.md verified fixtures)", () => {
  it("matches expectFinding for every fixture via findHighEntropyFindings", () => {
    for (const fixture of SHORT_PASSWORD_FIXTURES) {
      const findings = findHighEntropyFindings(fixture.content);
      expect(findings.length > 0, `fixture '${fixture.name}' expected finding=${fixture.expectFinding}`).toBe(
        fixture.expectFinding,
      );
    }
  });
});

// spec: openspec/specs/high-entropy-secret-detection/spec.md

describe("findUrlSpans", () => {
  it("finds an http(s) URL span up to the next whitespace", () => {
    const text = "see https://example.com/a/b for details";
    const spans = findUrlSpans(text);
    expect(spans).toHaveLength(1);
    expect(text.slice(spans[0].start, spans[0].end)).toBe("https://example.com/a/b");
  });

  it("finds no span in text with no recognized scheme", () => {
    expect(findUrlSpans("just a/b/c path, no scheme")).toEqual([]);
  });

  it("finds multiple independent URL spans in one message", () => {
    const text = "http://one.example/x and https://two.example/y";
    expect(findUrlSpans(text)).toHaveLength(2);
  });
});

describe("findCandidateRuns — URL path separator handling", () => {
  it("splits a run at '/' boundaries when the run overlaps a detected URL span", () => {
    const text = "https://example.com/ClarkSource/middleearth/README";
    const runs = findCandidateRuns(text);
    expect(runs.map((r) => r.text)).toEqual(["https", "example", "com", "ClarkSource", "middleearth", "README"]);
  });

  it("does not split a '/'-containing run that falls outside any URL span (regression guard)", () => {
    const text = "value=aGVsbG8/d29ybGQ end";
    const runs = findCandidateRuns(text);
    expect(runs.map((r) => r.text)).toEqual(["value=aGVsbG8/d29ybGQ", "end"]);
  });
});

describe("findHighEntropyFindings — URL path false-positive fix", () => {
  it("does not flag an ordinary multi-segment URL path as one high-entropy blob", () => {
    // a case-uniform 40-char lowercase hex commit id, glued pre-fix to the
    // surrounding org/repo/file path segments into one 70+ char base64-
    // classified run whose diversity trivially clears the 4.5 threshold.
    const commitId = "0123456789abcdef".repeat(3).slice(0, 40);
    const url = `https://raw.githubusercontent.com/ClarkSource/middleearth/${commitId}/README`;
    expect(findHighEntropyFindings(url)).toEqual([]);
  });

  it("Preserves complete URLs regardless of segment entropy", () => {
    // 36 distinct base64-alphabet characters (0-9, a-z once each):
    // H = log2(36) ≈ 5.17, comfortably above the 4.5 base64 threshold.
    const secret = Array.from({ length: 36 }, (_, i) => i.toString(36)).join("");
    const short = SHORT_PASSWORD_FIXTURES.find((fixture) => fixture.expectFinding).content;
    for (const token of [secret, short]) {
      for (const url of [
        `https://${token}.invalid/download/${token}/file`,
        `custom://${token}:${token}@example.invalid/?key=${token}#${token}`,
        `https://example.invalid/${token},${token};${token}`,
      ]) {
        expect(findHighEntropyFindings(url), url).toEqual([]);
      }
    }
  });

  it("Leaves unanchored slash-containing credentials detectable", () => {
    // a base64-shaped run containing '/', with no scheme:// prefix, so no
    // URL span is detected and the run is scored exactly as before this
    // change (unsplit).
    const secret = Array.from({ length: 36 }, (_, i) => i.toString(36)).join("");
    const withSlash = `${secret.slice(0, 18)}/${secret.slice(18)}`;
    const text = `value=${withSlash} end`;
    const findings = findHighEntropyFindings(text);
    expect(findings).toHaveLength(1);
    expect(text.slice(findings[0].start, findings[0].end)).toBe(`value=${withSlash}`);
  });

  it("keeps a crossing candidate intact for exemption subtraction", () => {
    const secret = Array.from({ length: 20 }, (_, i) => i.toString(36)).join("");
    const text = `${secret}/rest=https://example.com/a/b end`;
    const runs = findCandidateRuns(text);
    expect(runs[0].text).toBe(`${secret}/rest=https`);
  });
});

// spec: openspec/specs/high-entropy-secret-detection/spec.md

describe("findPathSpans", () => {
  it("finds one span covering a whole POSIX absolute path (T1)", () => {
    const text = "see /home/user/Projects/xK7bQ2mR9zP4vN6wJ8sL1tY3hG5dF/output for details";
    const spans = findPathSpans(text);
    expect(spans).toHaveLength(1);
    expect(text.slice(spans[0].start, spans[0].end)).toBe(
      "/home/user/Projects/xK7bQ2mR9zP4vN6wJ8sL1tY3hG5dF/output",  // pragma: allowlist secret
    );
  });

  it("covers a backtick-wrapped dot-broken path as a single span (T2 -- proves .worktrees/.venv share one span)", () => {
    const text = "`/home/user/.worktrees/PLT-885-slack-mention-dm-user-id/.venv`";
    const spans = findPathSpans(text);
    expect(spans).toHaveLength(1);
    expect(spans[0]).toEqual({ start: 1, end: 61 });
    // Slicing back to the path without either backtick proves the span's
    // `.`-inclusive body keeps `.worktrees` and `.venv` inside the same
    // span as the rest of the path, rather than stopping at the first `.`.
    expect(text.slice(spans[0].start, spans[0].end)).toBe(
      "/home/user/.worktrees/PLT-885-slack-mention-dm-user-id/.venv",
    );
  });

  it("anchors a Windows drive-letter forward-slash path at the drive letter, not the slash (T3)", () => {
    const text = "C:/Data/Builds/aB3xY7mK9qT2wR5vN8jH1sL4dF6gP0zC/x86_Rel";
    const spans = findPathSpans(text);
    expect(spans).toHaveLength(1);
    expect(spans[0].start).toBe(0);
    expect(text.slice(spans[0].start, spans[0].end)).toBe(text);
  });

  it("finds one span each for './', '../', and '~/' relative anchors (T4)", () => {
    expect(findPathSpans("./a/b/c")).toHaveLength(1);
    expect(findPathSpans("../a/b/c")).toHaveLength(1);
    expect(findPathSpans("~/a/b/c")).toHaveLength(1);
  });

  it("finds a span inside each bracket/quote pairing with no bracket characters included (T5)", () => {
    const text = "(/etc/hosts) [/tmp/x/y] {/a/b/c} </srv/www/x>";
    const spans = findPathSpans(text);
    expect(spans).toHaveLength(4);
    for (const span of spans) {
      const matched = text.slice(span.start, span.end);
      expect(matched).not.toMatch(/[()[\]{}<>]/);
    }
  });

  it("finds no span for an anchor not itself sitting at a boundary character (T6)", () => {
    expect(findPathSpans("PATH=/usr/bin:/usr/local/bin")).toEqual([]);
    expect(findPathSpans("x=./a/b")).toEqual([]);
    expect(findPathSpans("...../a/b")).toEqual([]);
    expect(findPathSpans("no-anchor-here/foo/bar")).toEqual([]);
    expect(findPathSpans("x=C:\\Users\\x")).toEqual([]);
  });

  it("finds no path span for a bare scheme:// URL (already governed by findUrlSpans) (T7)", () => {
    expect(findPathSpans("https://example.com/a/b")).toEqual([]);
  });

  it("recognizes a path containing '+'", () => {
    const secret36 = Array.from({ length: 36 }, (_, i) => i.toString(36)).join("");
    const text = `"${"/" + secret36.slice(0, 17) + "+" + secret36.slice(17, 18) + "/" + secret36.slice(18)}"`;
    expect(findPathSpans(text)).toEqual([{ start: 1, end: text.length - 1 }]);
  });

  it("recognizes a path containing '='", () => {
    const secret36 = Array.from({ length: 36 }, (_, i) => i.toString(36)).join("");
    const text = `"${"/" + secret36.slice(0, 17) + "/" + secret36.slice(17) + "="}"`;
    expect(findPathSpans(text)).toEqual([{ start: 1, end: text.length - 1 }]);
  });

  it("recognizes a single-component absolute path", () => {
    const secret36 = Array.from({ length: 36 }, (_, i) => i.toString(36)).join("");
    const text = `"${"/" + secret36}"`;
    expect(findPathSpans(text)).toEqual([{ start: 1, end: text.length - 1 }]);
  });
});

describe("findCandidateRuns — filesystem path separator handling", () => {
  it("splits a run at '/' boundaries when the run falls inside a path span (T11)", () => {
    const text = "/home/user/Projects/xK7bQ2mR9zP4vN6wJ8sL1tY3hG5dF/output";  // pragma: allowlist secret
    const runs = findCandidateRuns(text);
    expect(runs.map((r) => r.text)).toEqual([
      "home",
      "user",
      "Projects",
      "xK7bQ2mR9zP4vN6wJ8sL1tY3hG5dF",  // pragma: allowlist secret
      "output",
    ]);
  });

  it("does not split a '/'-containing run with no path anchor and no URL span (T12, regression guard)", () => {
    const text = "value=aGVsbG8/d29ybGQ end";
    const runs = findCandidateRuns(text);
    expect(runs.map((r) => r.text)).toEqual(["value=aGVsbG8/d29ybGQ", "end"]);
  });
});

describe("findHighEntropyFindings — filesystem path false-positive fix", () => {
  it("matches expectFinding for every PATH_FIXTURES entry (T13)", () => {
    for (const fixture of PATH_FIXTURES) {
      const findings = findHighEntropyFindings(fixture.content);
      expect(findings.length > 0, `fixture '${fixture.name}' expected finding=${fixture.expectFinding}`).toBe(
        fixture.expectFinding,
      );
    }
  });

  it("Preserves complete Linux and Windows filesystem paths", () => {
    const secret = Array.from({ length: 36 }, (_, i) => i.toString(36)).join("");
    const short = SHORT_PASSWORD_FIXTURES.find((fixture) => fixture.expectFinding).content;
    for (const token of [secret, short]) {
      for (const path of [
        `/${token}`, `/home/user/${token}/file.txt`, `./${token}`, `../${token}`,
        `~/${token}`, `C:/${token}/file`, `C:\\${token}\\file`,
        `\\\\server\\share\\${token}`, `.\\${token}`, `..\\${token}`, `~\\${token}`,
        `/${token}+suffix=`,
      ]) {
        expect(findHighEntropyFindings(`see \`${path}\` here`), path).toEqual([]);
      }
    }
  });

  it("preserves an anchored path made of diverse short components", () => {
    const blob = "/home/user/xK7bQ2z/mR9wQ3f/vN6sL1y/output";  // pragma: allowlist secret
    expect(shannonEntropy(blob)).toBeGreaterThan(4.5);
    const text = `secret: ${blob} end`;
    expect(findHighEntropyFindings(text)).toEqual([]);
  });
});
