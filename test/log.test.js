// spec: openspec/specs/plugin-logging/spec.md

import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLogger, normalizeLogConfig, DEFAULT_LOG_CONFIG } from "../src/log.js";

function capture() {
  const lines = [];
  return { lines, stderrWrite: (line) => lines.push(line) };
}

describe("createLogger", () => {
  it("writes warn and error to stderr by default and drops info/debug", () => {
    const { lines, stderrWrite } = capture();
    const logger = createLogger({ stderrWrite });
    logger.log("debug", "d");
    logger.log("info", "i");
    logger.log("warn", "w");
    logger.log("error", "e");
    expect(lines).toEqual(["[opencode-redact] [warn] w\n", "[opencode-redact] [error] e\n"]);
  });

  it("silent level writes nothing", () => {
    const { lines, stderrWrite } = capture();
    const logger = createLogger({ level: "silent", stderrWrite });
    logger.log("error", "e");
    logger.log("warn", "w");
    expect(lines).toEqual([]);
  });

  it("sink none writes nothing", () => {
    const { lines, stderrWrite } = capture();
    const logger = createLogger({ sink: "none", stderrWrite });
    logger.log("error", "e");
    expect(lines).toEqual([]);
  });

  it("file sink appends JSONL with fields and leaves stderr untouched", () => {
    const dir = mkdtempSync(join(tmpdir(), "redact-log-"));
    try {
      const file = join(dir, "redact.log");
      const { lines, stderrWrite } = capture();
      const logger = createLogger({ sink: "file", file, now: () => "T0", stderrWrite });
      logger.log("warn", "redacted 1 secret", { source: "tool-output", count: 1, ruleIds: ["aws"] });
      logger.log("info", "dropped at the warn threshold");
      const record = JSON.parse(readFileSync(file, "utf8").trim());
      expect(record).toEqual({
        ts: "T0",
        level: "warn",
        message: "redacted 1 secret",
        source: "tool-output",
        count: 1,
        ruleIds: ["aws"],
      });
      expect(lines).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rotates the file once it reaches maxBytes", () => {
    const dir = mkdtempSync(join(tmpdir(), "redact-log-"));
    try {
      const file = join(dir, "redact.log");
      writeFileSync(file, "x".repeat(50));
      const logger = createLogger({ sink: "file", file, maxBytes: 10, now: () => "T" });
      logger.log("warn", "after rotation");
      expect(existsSync(`${file}.1`)).toBe(true);
      expect(JSON.parse(readFileSync(file, "utf8").trim()).message).toBe("after rotation");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fails open when the sink throws", () => {
    const logger = createLogger({
      stderrWrite: () => {
        throw new Error("boom");
      },
    });
    expect(() => logger.log("warn", "x")).not.toThrow();
  });
});

describe("normalizeLogConfig", () => {
  it("returns defaults when the key is absent", () => {
    expect(normalizeLogConfig(undefined).value).toEqual(DEFAULT_LOG_CONFIG);
  });

  it("accepts a fully valid object without warnings", () => {
    const { value, warnings } = normalizeLogConfig({
      level: "info",
      sink: "file",
      file: "/tmp/x.log",
      maxBytes: 5,
    });
    expect(value).toEqual({ level: "info", sink: "file", file: "/tmp/x.log", maxBytes: 5 });
    expect(warnings).toEqual([]);
  });

  it("falls back per-key and warns on invalid values and unknown sub-keys", () => {
    const { value, warnings } = normalizeLogConfig({
      level: "loud",
      sink: "stdout",
      file: 5,
      maxBytes: -1,
      extra: true,
    });
    expect(value).toEqual(DEFAULT_LOG_CONFIG);
    expect(warnings).toHaveLength(5);
  });
});
