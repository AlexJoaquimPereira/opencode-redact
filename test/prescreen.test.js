// spec: openspec/specs/tool-output-redaction/spec.md
//
// Tests for the anchor-based prescreen, extracted from test/redact.test.js
// alongside src/prescreen.js's extraction from src/redact.js (design.md
// D2) — a pure move, not a behavior change.

import { describe, it, expect } from "vitest";
import * as preset from "@secretlint/secretlint-rule-preset-recommend";
import { RULE_FIXTURES } from "./fixtures.js";
import { looksLikeSecret } from "../src/prescreen.js";

// Pinned so a dependency bump that adds or removes a recommend-preset rule
// fails CI and forces a review of SECRET_ANCHOR_PATTERN/anchors: the prescreen
// must never skip content an anchored rule would flag.
const PINNED_PRESET_RULES = [
  "@secretlint/secretlint-rule-1password",
  "@secretlint/secretlint-rule-anthropic",
  "@secretlint/secretlint-rule-aws",
  "@secretlint/secretlint-rule-basicauth",
  "@secretlint/secretlint-rule-cloudflare",
  "@secretlint/secretlint-rule-database-connection-string",
  "@secretlint/secretlint-rule-databricks",
  "@secretlint/secretlint-rule-docker",
  "@secretlint/secretlint-rule-figma",
  "@secretlint/secretlint-rule-filter-comments",
  "@secretlint/secretlint-rule-gcp",
  "@secretlint/secretlint-rule-github",
  "@secretlint/secretlint-rule-gitlab",
  "@secretlint/secretlint-rule-grafana",
  "@secretlint/secretlint-rule-groq",
  "@secretlint/secretlint-rule-hashicorp-vault",
  "@secretlint/secretlint-rule-huggingface",
  "@secretlint/secretlint-rule-linear",
  "@secretlint/secretlint-rule-notion",
  "@secretlint/secretlint-rule-npm",
  "@secretlint/secretlint-rule-openai",
  "@secretlint/secretlint-rule-privatekey",
  "@secretlint/secretlint-rule-sendgrid",
  "@secretlint/secretlint-rule-shopify",
  "@secretlint/secretlint-rule-slack",
  "@secretlint/secretlint-rule-stripe",
  "@secretlint/secretlint-rule-tailscale",
  "@secretlint/secretlint-rule-vercel",
];

describe("preset/anchor completeness guard", () => {
  it("pins the installed recommend-preset rule set (dependency-bump tripwire)", () => {
    const ids = (preset.rules ?? [])
      .map((rule) => rule?.meta?.id ?? rule?.id)
      .filter(Boolean);
    expect([...ids].sort()).toEqual([...PINNED_PRESET_RULES].sort());
  });
});

describe("looksLikeSecret", () => {
  it("does not skip a positive fixture for any rule", () => {
    for (const fixture of RULE_FIXTURES) {
      expect(
        looksLikeSecret(fixture.content),
        `expected looksLikeSecret to return true for rule '${fixture.rule}' fixture`,
      ).toBe(true);
    }
  });

  it("returns false for clean, unremarkable text", () => {
    expect(looksLikeSecret("the quick brown fox jumps over the lazy dog")).toBe(false);
  });

  it("returns false for an empty string", () => {
    expect(looksLikeSecret("")).toBe(false);
  });

  it("is case-insensitive", () => {
    expect(looksLikeSecret("AWS_SECRET_ACCESS_KEY=x")).toBe(true);
    expect(looksLikeSecret("aws_secret_access_key=x")).toBe(true);
  });
});
