// spec: openspec/changes/v2-plugin-migration/specs/tool-output-redaction/spec.md
// spec: openspec/changes/v2-plugin-migration/specs/user-message-redaction/spec.md
//
// Layer-2 adapter-conformance suite (design.md D9): drives a shared fixture
// corpus through a fake V1 host and a fake V2 ctx, asserting the two
// adapters produce string-identical redacted text, identical annotations,
// and identical log content — the property that stops the two adapters
// drifting apart. V2-only shape-specific cases (Content[] walk, tool-error
// skip, output fallback), lifecycle, and invariant cases follow.
import { describe, it, expect, vi } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import PluginV1 from "../src/plugin.v1.js";
import PluginV2 from "../src/plugin.v2.js";
import { RULE_FIXTURES } from "./fixtures.js";

const SRC_DIR = fileURLToPath(new URL("../src/", import.meta.url));

function fakeV1Client() {
  return { app: { log: vi.fn().mockResolvedValue(undefined) } };
}

/**
 * A fake V2 ctx exposing exactly what setup() touches: tool.hook and
 * session.hook as capturing stubs that record the callback and resolve to
 * a disposable Registration, matching the real `(name, cb) => Promise<Registration>`
 * shape (design.md "Verified platform facts").
 */
function fakeV2Ctx() {
  const hooks = { "execute.after": null, prompt: null, context: null, generate: null, compaction: null, title: null };
  const disposals = {
    "execute.after": vi.fn().mockResolvedValue(undefined),
    prompt: vi.fn().mockResolvedValue(undefined),
    context: vi.fn().mockResolvedValue(undefined),
    generate: vi.fn().mockResolvedValue(undefined),
    compaction: vi.fn().mockResolvedValue(undefined),
    title: vi.fn().mockResolvedValue(undefined),
  };
  const ctx = {
    tool: {
      hook: vi.fn(async (name, cb) => {
        hooks[name] = cb;
        return { dispose: disposals[name] };
      }),
    },
    session: {
      hook: vi.fn(async (name, cb) => {
        hooks[name] = cb;
        return { dispose: disposals[name] };
      }),
    },
  };
  return { ctx, hooks, disposals };
}

async function loadV1() {
  const client = fakeV1Client();
  const v1Hooks = await PluginV1({ client });
  return { client, v1Hooks };
}

async function loadV2(testOverrides = {}) {
  const { ctx, hooks, disposals } = fakeV2Ctx();
  const cleanup = await PluginV2.setup(ctx, testOverrides);
  return { ctx, hooks, disposals, cleanup };
}

/** Captures process.stderr.write for the duration of a callback. */
async function captureStderr(fn) {
  const original = process.stderr.write.bind(process.stderr);
  const lines = [];
  process.stderr.write = (chunk) => {
    lines.push(String(chunk));
    return true;
  };
  try {
    return { result: await fn(), lines };
  } finally {
    process.stderr.write = original;
  }
}

const CLEAN_TEXT = "nothing sensitive at all";
const CORPUS = [
  { name: "clean", text: CLEAN_TEXT, expectRedaction: false },
  // Exclude "gcp": it requires ext:".json" context (see test/fixtures.js's
  // own comment) that a plain string-based harness like this one doesn't
  // provide, so it would never trigger regardless of adapter correctness.
  ...RULE_FIXTURES.filter((f) => f.rule !== "gcp")
    .slice(0, 3)
    .map((f) => ({ name: f.rule, text: `secret=${f.content}`, expectRedaction: true })),
];

describe("V1/V2 adapter conformance — tool-output redaction", () => {
  for (const fixture of CORPUS) {
    it(`${fixture.name}: redacted text and log content are identical across V1 and V2`, async () => {
      const { client, v1Hooks } = await loadV1();
      const v1Output = { output: fixture.text, metadata: {} };
      await v1Hooks["tool.execute.after"]({ tool: "bash" }, v1Output);

      const { hooks: v2Hooks } = await loadV2();
      const v2Event = { tool: "bash", status: "completed", result: { content: fixture.text } };
      const { lines } = await captureStderr(() => v2Hooks["execute.after"](v2Event));

      expect(v2Event.result.content).toBe(v1Output.output);

      if (fixture.expectRedaction) {
        expect(v1Output.output).toContain("***REDACTED:");
        expect(client.app.log).toHaveBeenCalled();
        expect(lines.some((l) => l.includes("[warn]"))).toBe(true);
      } else {
        expect(v1Output.output).toBe(CLEAN_TEXT);
        expect(client.app.log).not.toHaveBeenCalled();
        expect(lines).toEqual([]);
      }
    });
  }
  it("V1 tool.execute.after redacts a secret in metadata (parity with V2)", async () => {
    const { v1Hooks } = await loadV1();
    const secret = RULE_FIXTURES[0].content;
    const v1Output = { output: "clean text", metadata: { note: `leak=${secret}` } };
    await v1Hooks["tool.execute.after"]({ tool: "bash" }, v1Output);
    expect(v1Output.output).toBe("clean text");
    expect(v1Output.metadata.note).toContain("***REDACTED:");
    expect(v1Output.metadata.note).not.toContain(secret);
  });
});

describe("V1/V2 adapter conformance — user-message redaction", () => {
  for (const fixture of CORPUS) {
    it(`${fixture.name}: redacted text and annotation are identical across V1 and V2`, async () => {
      const { client, v1Hooks } = await loadV1();
      const part = { type: "text", text: fixture.text };
      const v1Output = { message: {}, parts: [part] };
      await v1Hooks["chat.message"]({ sessionID: "s1" }, v1Output);

      const { hooks: v2Hooks } = await loadV2();
      const v2Event = { sessionID: "s1", prompt: { text: fixture.text } };
      const { lines } = await captureStderr(() => v2Hooks.prompt(v2Event));

      expect(v2Event.prompt.text).toBe(part.text);

      if (fixture.expectRedaction) {
        expect(part.text).toContain("***REDACTED:");
        const annotationCount = (part.text.match(/\[opencode-redact\]/g) ?? []).length;
        expect(annotationCount).toBe(1);
        expect(client.app.log).toHaveBeenCalled();
        expect(lines.some((l) => l.includes("[warn]"))).toBe(true);
      } else {
        expect(part.text).toBe(CLEAN_TEXT);
        expect(client.app.log).not.toHaveBeenCalled();
        expect(lines).toEqual([]);
      }
    });
  }

  it("V2: a noredact-fenced secret is left untouched, matching V1's fence exemption", async () => {
    const secret = RULE_FIXTURES[0].content;
    const fenced = `\`\`\`noredact\nsecret=${secret}\n\`\`\``;

    const { v1Hooks } = await loadV1();
    const part = { type: "text", text: fenced };
    await v1Hooks["chat.message"]({ sessionID: "s1" }, { message: {}, parts: [part] });

    const { hooks: v2Hooks } = await loadV2();
    const v2Event = { sessionID: "s1", prompt: { text: fenced } };
    await v2Hooks.prompt(v2Event);

    expect(v2Event.prompt.text).toBe(fenced);
    expect(part.text).toBe(fenced);
  });

  it("V2: redaction survives even when the annotation-append write throws (mirrors V1's tested guarantee)", async () => {
    const secret = RULE_FIXTURES[0].content;
    const original = `secret=${secret}`;
    let value = original;
    let writes = 0;
    const { hooks } = await loadV2();
    const v2Event = {
      sessionID: "s1",
      prompt: {
        get text() {
          return value;
        },
        set text(v) {
          writes += 1;
          if (writes === 2) {
            throw new Error("second write boom");
          }
          value = v;
        },
      },
    };

    await hooks.prompt(v2Event);

    expect(v2Event.prompt.text).toContain("***REDACTED:");
    expect(v2Event.prompt.text).not.toContain(secret);
    expect(v2Event.prompt.text).not.toContain("[opencode-redact]");
    expect(writes).toBe(2);
  });
});

describe("V2-only shape-specific cases", () => {
  it('execute.after: redacts a secret in a non-enumerable error message (Tool.Error shape)', async () => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const error = { metadata: { note: `meta ${secret}` } };
    // Host `Tool.Error.message`/`.stack` are non-enumerable own properties;
    // simulate that so a regression back to `Object.keys` fails here.
    Object.defineProperty(error, "message", {
      value: `leak ${secret}`,
      enumerable: false,
      writable: true,
      configurable: true,
    });
    const event = { tool: "bash", status: "error", error };
    await hooks["execute.after"](event);
    expect(event.error.message).toContain("***REDACTED:");
    expect(event.error.message).not.toContain(secret);
    expect(event.error.metadata.note).toContain("***REDACTED:");
    expect(event.error.metadata.note).not.toContain(secret);
  });

  it("execute.after: Content[] walk redacts text blocks, leaves file blocks untouched, one annotation on the last redacted block", async () => {
    const { hooks } = await loadV2();
    const secretA = RULE_FIXTURES.find((f) => f.rule === "aws").content;
    const secretB = RULE_FIXTURES.find((f) => f.rule === "privatekey").content;
    const event = {
      tool: "bash",
      status: "completed",
      result: {
        content: [
          { type: "text", text: `first=${secretA}` },
          { type: "file", uri: "file:///tmp/x", mime: "text/plain" },
          { type: "text", text: `second=${secretB}` },
        ],
      },
    };
    await hooks["execute.after"](event);

    expect(event.result.content[0].text).toContain("***REDACTED:");
    expect(event.result.content[0].text).not.toContain("[opencode-redact]");
    expect(event.result.content[1]).toEqual({ type: "file", uri: "file:///tmp/x", mime: "text/plain" });
    expect(event.result.content[2].text).toContain("***REDACTED:");
    const annotationCount = (event.result.content[2].text.match(/\[opencode-redact\]/g) ?? []).length;
    expect(annotationCount).toBe(1);
  });

  it("execute.after: output is redacted only when content is absent and output is a string", async () => {
    const { hooks: hooksWithoutContent } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const eventStringOutput = { tool: "bash", status: "completed", result: { output: `leak=${secret}` } };
    await hooksWithoutContent["execute.after"](eventStringOutput);
    expect(eventStringOutput.result.output).toContain("***REDACTED:");

    const { hooks: hooksStructured } = await loadV2();
    const structuredOutput = { data: { token: secret } };
    const eventStructuredOutput = { tool: "bash", status: "completed", result: { output: structuredOutput } };
    await hooksStructured["execute.after"](eventStructuredOutput);
    expect(eventStructuredOutput.result.output).toBe(structuredOutput);

    const { hooks: hooksBothPresent } = await loadV2();
    const eventBothPresent = {
      tool: "bash",
      status: "completed",
      result: { content: "clean text", output: `leak=${secret}` },
    };
    await hooksBothPresent["execute.after"](eventBothPresent);
    // content present -> output is never consulted, even though it has a secret.
    expect(eventBothPresent.result.output).toBe(`leak=${secret}`);
  });

  it("execute.after: a structured {exit, truncated, output} record's nested output.output string is redacted even when content is also present (real @opencode/cli 2.0.4 shell-tool shape)", async () => {
    // Empirically confirmed shape: the built-in shell tool's result.output
    // is NOT a bare string OR arbitrary opaque data -- it's a structured
    // record duplicating the same raw text content already carries. This
    // must be redacted too, independently of content, or the secret
    // survives in this parallel field.
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const event = {
      tool: "shell",
      status: "completed",
      result: {
        content: [{ type: "text", text: `leak=${secret}\n` }, { type: "text", text: "Command exited with code 0." }],
        output: { exit: 0, truncated: false, output: `leak=${secret}\n`, status: "completed" },
      },
    };
    await hooks["execute.after"](event);

    expect(event.result.content[0].text).toContain("***REDACTED:");
    expect(event.result.content[0].text).not.toContain(secret);
    expect(event.result.output.output).toContain("***REDACTED:");
    expect(event.result.output.output).not.toContain(secret);
    // Non-output-related fields of the structured output are preserved.
    expect(event.result.output.exit).toBe(0);
    expect(event.result.output.truncated).toBe(false);
    expect(event.result.output.status).toBe("completed");
  });

  it("execute.after: a structured output record's nested output.output is left untouched when it has no secret", async () => {
    const { hooks } = await loadV2();
    const event = {
      tool: "shell",
      status: "completed",
      result: {
        content: [{ type: "text", text: "nothing sensitive\n" }],
        output: { exit: 0, truncated: false, output: "nothing sensitive\n", status: "completed" },
      },
    };
    const before = JSON.stringify(event.result.output);
    await hooks["execute.after"](event);
    expect(JSON.stringify(event.result.output)).toBe(before);
  });

  it("execute.after: annotates a redaction carried only by a structured output.output (content absent)", async () => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const event = { tool: "shell", status: "completed", result: { output: { exit: 0, output: `leak=${secret}` } } };
    await hooks["execute.after"](event);
    expect(event.result.output.output).toContain("***REDACTED:");
    expect(event.result.output.output).not.toContain(secret);
    expect(event.result.output.output).toContain("[opencode-redact]");
  });

  it("execute.after: event.result is replaced wholesale (readonly fields)", async () => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const originalResult = Object.freeze({ content: `leak=${secret}`, metadata: { durationMs: 42 } });
    const event = { tool: "bash", status: "completed", result: originalResult };
    await hooks["execute.after"](event);
    expect(event.result).not.toBe(originalResult);
    expect(event.result.metadata).toEqual({ durationMs: 42 });
    expect(event.result.content).toContain("***REDACTED:");
  });

  it("execute.after: a secret in the tool result's metadata is redacted", async () => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const originalResult = Object.freeze({
      content: "clean text",
      metadata: { durationMs: 42, note: `leak=${secret}` },
    });
    const event = { tool: "bash", status: "completed", result: originalResult };
    await hooks["execute.after"](event);
    expect(event.result.metadata.note).toContain("***REDACTED:");
    expect(event.result.metadata.note).not.toContain(secret);
    expect(event.result.metadata.durationMs).toBe(42);
    expect(event.result.content).toBe("clean text");
  });

  it("execute.after: an unusually large structured result does not block indefinitely", async () => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const bigClean = "x".repeat(250_000);
    const originalResult = Object.freeze({
      content: "clean text",
      metadata: { blob: bigClean, note: `leak=${secret}` },
    });
    const event = { tool: "bash", status: "completed", result: originalResult };
    const start = Date.now();
    await hooks["execute.after"](event);
    expect(Date.now() - start).toBeLessThan(5000);
    // The budget may leave the tail unscanned; the result must not hang or throw.
    expect(typeof event.result.metadata.blob).toBe("string");
  });
});

// spec: openspec/specs/request-payload-redaction/spec.md
describe("V2-only shape-specific cases — session context/generate/compaction hooks", () => {
  const HOOK_NAMES = ["context", "generate", "compaction", "title"];

  it("setup registers context, generate, and compaction session hooks", async () => {
    const { ctx } = await loadV2();
    for (const name of HOOK_NAMES) {
      expect(ctx.session.hook).toHaveBeenCalledWith(name, expect.any(Function));
    }
  });

  for (const name of HOOK_NAMES) {
    it(`${name}: redacts a known-detectable secret in a system prompt segment`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const event = {
        sessionID: "s1",
        system: [{ type: "text", text: `leak=${secret}` }],
        messages: [],
      };
      await hooks[name](event);
      expect(event.system[0].text).toContain("***REDACTED:");
      expect(event.system[0].text).not.toContain(secret);
      const annotationCount = (event.system[0].text.match(/\[opencode-redact\]/g) ?? []).length;
      expect(annotationCount).toBe(1);
    });

    it(`${name}: leaves a clean system prompt segment unchanged`, async () => {
      const { hooks } = await loadV2();
      const event = {
        sessionID: "s1",
        system: [{ type: "text", text: CLEAN_TEXT }],
        messages: [],
      };
      await hooks[name](event);
      expect(event.system[0].text).toBe(CLEAN_TEXT);
    });

    it(`${name}: redacts a secret in a message's text content`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const event = {
        sessionID: "s1",
        system: [],
        messages: [{ role: "user", content: [{ type: "text", text: `leak=${secret}` }] }],
      };
      await hooks[name](event);
      expect(event.messages[0].content[0].text).toContain("***REDACTED:");
      expect(event.messages[0].content[0].text).not.toContain(secret);
    });

    it(`${name}: redacts a secret in a tool-call input (tightened)`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const toolCallBlock = { type: "tool-call", id: "1", name: "bash", input: { cmd: `leak=${secret}` } };
      const event = {
        sessionID: "s1",
        system: [],
        messages: [{ role: "assistant", content: [toolCallBlock] }],
      };
      await hooks[name](event);
      expect(event.messages[0].content[0].input.cmd).toContain("***REDACTED:");
      expect(event.messages[0].content[0].input.cmd).not.toContain(secret);
    });

    it(`${name}: redacts a secret in a tool-result value (tightened)`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const event = {
        sessionID: "s1",
        system: [],
        messages: [
          {
            role: "tool",
            content: [
              {
                type: "tool-result",
                id: "1",
                name: "bash",
                result: { type: "error", value: { message: `leak ${secret}` } },
              },
            ],
          },
        ],
      };
      await hooks[name](event);
      const serialized = JSON.stringify(event.messages[0].content[0]);
      expect(serialized).toContain("***REDACTED:");
      expect(serialized).not.toContain(secret);
    });

    it(`${name}: redacts a non-enumerable message inside a tool-result value (tightened)`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const value = {};
      Object.defineProperty(value, "message", {
        value: `leak ${secret}`,
        enumerable: false,
        writable: true,
        configurable: true,
      });
      const event = {
        sessionID: "s1",
        system: [],
        messages: [
          {
            role: "tool",
            content: [
              { type: "tool-result", id: "1", name: "bash", result: { type: "error", value } },
            ],
          },
        ],
      };
      await hooks[name](event);
      const stored = event.messages[0].content[0].result.value;
      expect(stored.message).toContain("***REDACTED:");
      expect(stored.message).not.toContain(secret);
    });

    it(`${name}: leaves a reasoning part with its providerMetadata untouched (signed-reasoning exemption)`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const reasoningPart = {
        type: "reasoning",
        text: `think ${secret}`,
        providerMetadata: { anthropic: { signature: "sig-for-signed-thinking", redacted: false } },
      };
      const event = {
        sessionID: "s1",
        system: [],
        messages: [{ role: "assistant", content: [reasoningPart] }],
      };
      await hooks[name](event);
      expect(event.messages[0].content[0]).toBe(reasoningPart);
      expect(event.messages[0].content[0].text).toBe(`think ${secret}`);
      expect(event.messages[0].content[0].providerMetadata).toEqual({
        anthropic: { signature: "sig-for-signed-thinking", redacted: false },
      });
    });

    it(`${name}: a tool-call/tool-result-only redaction has no text part to annotate`, async () => {
      // Ownership + annotation coverage (review comment 2, and the spec's
      // "No text-bearing part to carry the annotation" scenario): when every
      // redaction lands in a part with no `.text`, the payload is still
      // redacted, but no annotation is appended because no text-bearing part
      // exists to carry it. The genuine copy-on-write guarantees are pinned
      // by the deep-frozen-parts and untouched-originals tests below.
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const event = {
        sessionID: "s1",
        system: [],
        messages: [
          {
            role: "assistant",
            content: [
              { type: "tool-call", id: "1", name: "bash", input: { cmd: `echo ${secret}` } },
              {
                type: "tool-result",
                id: "1",
                name: "bash",
                result: { type: "json", value: { out: `leak ${secret}` } },
              },
            ],
          },
        ],
      };
      await hooks[name](event);
      const content = event.messages[0].content;
      expect(content[0].input.cmd).toContain("***REDACTED:");
      expect(content[0].input.cmd).not.toContain(secret);
      expect(content[1].result.value.out).toContain("***REDACTED:");
      expect(content[1].result.value.out).not.toContain(secret);
      // No text-bearing part exists, so no annotation is appended anywhere.
      expect(JSON.stringify(content)).not.toContain("[opencode-redact]");
    });

    it(`${name}: annotates a compaction redaction (a text-bearing part)`, async () => {
      // The note goes on the last redacted part that carries a string `.text`,
      // which now also covers a `compaction` summary (previously text-only).
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const event = {
        sessionID: "s1",
        system: [],
        messages: [{ role: "assistant", content: [{ type: "compaction", text: `summary ${secret}` }] }],
      };
      await hooks[name](event);
      const part = event.messages[0].content[0];
      expect(part.text).toContain("***REDACTED:");
      expect(part.text).not.toContain(secret);
      expect(part.text).toContain("[opencode-redact]");
    });

    it(`${name}: writes only fresh array slots — deep-frozen part objects are never modified`, async () => {
      // The real copy-on-write pin for the review's ownership request: array
      // slots are replaced, but no part object and no nested container is
      // ever written in place. Freezing every part recursively makes any
      // in-place write throw (strict mode), failing the test loudly instead
      // of asserting the negative.
      const deepFreeze = (value) => {
        if (value && typeof value === "object" && !Object.isFrozen(value)) {
          Object.freeze(value);
          for (const key of Object.getOwnPropertyNames(value)) deepFreeze(value[key]);
        }
        return value;
      };
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const systemSeg = deepFreeze({ type: "text", text: `sys ${secret}` });
      const textPart = deepFreeze({ type: "text", text: `msg ${secret}` });
      const callPart = deepFreeze({ type: "tool-call", id: "1", name: "bash", input: { cmd: `echo ${secret}` } });
      const resultPart = deepFreeze({
        type: "tool-result",
        id: "1",
        name: "bash",
        result: { type: "json", value: { out: `leak ${secret}` } },
      });
      const event = {
        sessionID: "s1",
        system: [systemSeg],
        messages: [{ role: "assistant", content: [textPart, callPart, resultPart] }],
      };
      await expect(hooks[name](event)).resolves.toBeUndefined();
      expect(JSON.stringify(event)).toContain("***REDACTED:");
      expect(JSON.stringify(event)).not.toContain(secret);
    });

    it(`${name}: replaced slots leave the original part objects untouched`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const textPart = { type: "text", text: `msg ${secret}` };
      const callPart = { type: "tool-call", id: "1", name: "bash", input: { cmd: `echo ${secret}` } };
      const resultPart = {
        type: "tool-result",
        id: "1",
        name: "bash",
        result: { type: "json", value: { out: `leak ${secret}` } },
      };
      const untouchedText = { type: "text", text: "nothing sensitive here" };
      const event = {
        sessionID: "s1",
        system: [],
        messages: [{ role: "assistant", content: [textPart, callPart, resultPart, untouchedText] }],
      };
      await hooks[name](event);
      const content = event.messages[0].content;
      expect(content[0]).not.toBe(textPart);
      expect(content[1]).not.toBe(callPart);
      expect(content[2]).not.toBe(resultPart);
      expect(content[3]).toBe(untouchedText);
      // The ORIGINAL inputs the host still holds keep their raw values.
      expect(textPart.text).toBe(`msg ${secret}`);
      expect(callPart.input.cmd).toBe(`echo ${secret}`);
      expect(resultPart.result.value.out).toBe(`leak ${secret}`);
    });

    it(`${name}: leaves media and effort parts untouched`, async () => {
      const { hooks } = await loadV2();
      const mediaPart = {
        type: "media",
        media: { source: { type: "base64", data: "AAAA", mediaType: "image/png" } },
      };
      const effortPart = { type: "effort", effort: "high" };
      const event = {
        sessionID: "s1",
        system: [],
        messages: [{ role: "assistant", content: [mediaPart, effortPart] }],
      };
      await hooks[name](event);
      expect(event.messages[0].content[0]).toBe(mediaPart);
      expect(event.messages[0].content[1]).toBe(effortPart);
    });

    it(`${name}: one annotation for multiple redactions in the system prompt`, async () => {
      const { hooks } = await loadV2();
      const secretA = RULE_FIXTURES.find((f) => f.rule === "aws").content;
      const secretB = RULE_FIXTURES.find((f) => f.rule === "privatekey").content;
      const event = {
        sessionID: "s1",
        system: [
          { type: "text", text: `first=${secretA}` },
          { type: "text", text: `second=${secretB}` },
        ],
        messages: [],
      };
      await hooks[name](event);
      expect(event.system[0].text).not.toContain("[opencode-redact]");
      expect(event.system[1].text).toContain("[opencode-redact]");
      const totalAnnotations =
        (event.system[0].text.match(/\[opencode-redact\]/g) ?? []).length +
        (event.system[1].text.match(/\[opencode-redact\]/g) ?? []).length;
      expect(totalAnnotations).toBe(1);
    });

    it(`${name}: no annotation when no redaction occurred`, async () => {
      const { hooks } = await loadV2();
      const event = {
        sessionID: "s1",
        system: [{ type: "text", text: CLEAN_TEXT }],
        messages: [{ role: "user", content: [{ type: "text", text: CLEAN_TEXT }] }],
      };
      await hooks[name](event);
      expect(event.system[0].text).toBe(CLEAN_TEXT);
      expect(event.messages[0].content[0].text).toBe(CLEAN_TEXT);
    });
  }
});

// spec: openspec/specs/request-payload-redaction/spec.md
describe("V2 user-role noredact request rescans", () => {
  const secret = RULE_FIXTURES.find((f) => f.rule === "aws").content;
  const secondSecret = RULE_FIXTURES.find((f) => f.rule === "privatekey").content;
  const fenced = `\`\`\`noredact\n${secret}\n\`\`\``;
  const hookNames = ["context", "generate", "compaction"];
  // Keep annotation/count assertions independent of overlapping entropy findings.
  const testOverrides = { _loadPluginConfigOverride: async () => ({ disableHighEntropy: true }) };
  const textBlock = (text) => ({ type: "text", text });
  const userEvent = (...blocks) => ({ system: [], messages: [{ role: "user", content: blocks }] });

  it("User-role fences survive chained and repeated rescans", async () => {
    const { hooks } = await loadV2(testOverrides);
    const prompt = { prompt: { text: `${fenced}\noutside=${secondSecret}` } };
    await hooks.prompt(prompt);
    expect(prompt.prompt.text).toContain(fenced);
    expect(prompt.prompt.text).not.toContain(secondSecret);
    const event = userEvent(textBlock(prompt.prompt.text));
    const admittedText = prompt.prompt.text;
    for (const name of [...hookNames, ...hookNames]) {
      await hooks[name](event);
      expect(event.messages[0].content[0].text).toBe(admittedText);
    }
    event.messages[0].content[0].text += `\nnew=${secondSecret}`;
    await hooks.context(event);
    expect(event.messages[0].content[0].text).toContain(fenced);
    expect(event.messages[0].content[0].text).not.toContain(secondSecret);
    expect(event.messages[0].content[0].text.match(/\[opencode-redact\]/g)).toHaveLength(2);
  });

  for (const name of hookNames) {
    describe(name, () => {
      it("User-role fences survive each request-assembly stage", async () => {
        const { hooks } = await loadV2(testOverrides);
        const event = userEvent(textBlock(fenced));
        await hooks[name](event);
        expect(event.messages[0].content[0].text).toBe(fenced);
        await hooks[name](event);
        expect(event.messages[0].content[0].text).toBe(fenced);
      });

      it("Mixed user-role blocks retain aggregate annotations", async () => {
        const { hooks } = await loadV2(testOverrides);
        const nonText = { type: "reasoning", text: secret };
        const blocks = [
          { ...textBlock(`outside=${secret}\n${fenced}`), metadata: { note: "keep" } },
          nonText,
          textBlock(`outside=${secondSecret}`),
          textBlock(fenced),
        ];
        const event = userEvent(...blocks);
        await hooks[name](event);
        const content = event.messages[0].content;
        expect(content[0].text).toContain(fenced);
        expect(content[0].text.replace(fenced, "")).not.toContain(secret);
        expect(content[0].text).not.toContain("[opencode-redact]");
        expect(content[0].metadata).toEqual({ note: "keep" });
        expect(content[1]).toBe(nonText);
        expect(content[2].text).not.toContain(secondSecret);
        expect(content[2].text).toContain("2 secret(s)");
        expect(content[2].text).toContain("rules: aws+privatekey");
        expect(content[2].text.match(/\[opencode-redact\]/g)).toHaveLength(1);
        expect(content[3].text).toBe(fenced);
      });

      it("Malformed user-role fences remain scanned", async () => {
        const { hooks } = await loadV2(testOverrides);
        for (const text of [
          `\`\`\`noredact extra\n${secret}\n\`\`\``,
          `\`\`\`noredact\n${secret}`,
          `\`\`\`noredact\n${secret}\n\`\`\`\``,
        ]) {
          const event = userEvent(textBlock(text));
          await hooks[name](event);
          expect(event.messages[0].content[0].text).not.toContain(secret);
          expect(event.messages[0].content[0].text).toContain("***REDACTED:");
        }
      });

      it("Fences cannot span text blocks or messages", async () => {
        const { hooks } = await loadV2(testOverrides);
        const split = [textBlock(`\`\`\`noredact\n${secret}`), textBlock(`${secret}\n\`\`\``)];
        for (const messages of [
          [{ role: "user", content: structuredClone(split) }],
          split.map((block) => ({ role: "user", content: [structuredClone(block)] })),
        ]) {
          const event = { system: [], messages };
          await hooks[name](event);
          for (const message of event.messages) {
            for (const block of message.content) expect(block.text).not.toContain(secret);
          }
        }
      });

      it("Non-user roles receive no fence exemption", async () => {
        const { hooks } = await loadV2(testOverrides);
        const roles = ["system", "assistant", "tool", "unknown", undefined, "User", null, 1];
        const event = {
          system: [textBlock(fenced)],
          messages: roles.map((role) => ({ ...(role === undefined ? {} : { role }), content: [textBlock(fenced)] })),
        };
        await hooks[name](event);
        expect(event.system[0].text).not.toContain(secret);
        for (const message of event.messages) {
          expect(message.content[0].text).not.toContain(secret);
          expect(message.content[0].text).toContain("***REDACTED:");
        }
      });

      it("User-role exemption does not require human-authorship metadata", async () => {
        const { hooks } = await loadV2(testOverrides);
        const texts = [fenced, `File contents:\n${fenced}`, `<conversation-checkpoint>\n<summary>\n${fenced}\n</summary>\n</conversation-checkpoint>`];
        const event = { system: [], messages: texts.map((text) => ({ role: "user", content: [textBlock(text)] })) };
        await hooks[name](event);
        expect(event.messages.map((message) => message.content[0].text)).toEqual(texts);
      });

      it("User-role rescan failures retain fail-open behavior", async () => {
        const { hooks } = await loadV2({
          ...testOverrides,
          _createLinterOverride: () => async () => { throw new Error("scanner unavailable"); },
        });
        const text = `${fenced}\noutside=${secondSecret}`;
        const event = userEvent(textBlock(text));
        await expect(hooks[name](event)).resolves.toBeUndefined();
        expect(event.messages[0].content[0].text).toBe(text);
      });
    });
  }

  // spec: openspec/specs/tool-output-redaction/spec.md
  it("noredact fences in tool output do not exempt secrets from redaction", async () => {
    const { hooks } = await loadV2(testOverrides);
    const event = { tool: "shell", status: "completed", result: { content: [textBlock(fenced)] } };
    await hooks["execute.after"](event);
    expect(event.result.content[0].text).not.toContain(secret);
    expect(event.result.content[0].text).toContain("***REDACTED:");
  });
});

describe("lifecycle", () => {
  it("setup awaits all hook registrations and returns a cleanup that disposes all of them", async () => {
    const { ctx, disposals, cleanup } = await loadV2();
    expect(ctx.tool.hook).toHaveBeenCalledWith("execute.after", expect.any(Function));
    expect(ctx.session.hook).toHaveBeenCalledWith("prompt", expect.any(Function));
    expect(ctx.session.hook).toHaveBeenCalledWith("context", expect.any(Function));
    expect(ctx.session.hook).toHaveBeenCalledWith("generate", expect.any(Function));
    expect(ctx.session.hook).toHaveBeenCalledWith("compaction", expect.any(Function));
    await cleanup();
    for (const key of ["execute.after", "prompt", "context", "generate", "compaction", "title"]) {
      expect(disposals[key]).toHaveBeenCalled();
    }
  });

  it("a throwing dispose does not prevent the other registrations' disposal", async () => {
    const { ctx } = fakeV2Ctx();
    const disposeToolFail = vi.fn().mockRejectedValue(new Error("dispose boom"));
    const disposeSession = vi.fn().mockResolvedValue(undefined);
    ctx.tool.hook = vi.fn(async (_name, _cb) => ({ dispose: disposeToolFail }));
    ctx.session.hook = vi.fn(async (_name, _cb) => ({ dispose: disposeSession }));
    const cleanup = await PluginV2.setup(ctx);
    await cleanup();
    expect(disposeToolFail).toHaveBeenCalled();
    expect(disposeSession).toHaveBeenCalled();
  });

  it("a failing secretlint config load rejects out of setup after logging at error", async () => {
    const { ctx } = fakeV2Ctx();
    const brokenConfig = async () => {
      throw new Error("secretlint preset failed to resolve");
    };
    const { lines } = await captureStderr(() =>
      expect(PluginV2.setup(ctx, { _createSecretlintConfigOverride: brokenConfig })).rejects.toThrow(
        "secretlint preset failed to resolve",
      ),
    );
    expect(lines.some((l) => l.includes("[error]") && l.includes("secretlint"))).toBe(true);
    // Neither hook was registered -- setup failed before reaching them.
    expect(ctx.tool.hook).not.toHaveBeenCalled();
    expect(ctx.session.hook).not.toHaveBeenCalled();
  });
});

describe("export-surface invariants (widened to cover plugin.v2.js)", () => {
  it("plugin.v2.js has only a default export", async () => {
    const mod = await import("../src/plugin.v2.js");
    const keys = Object.keys(mod).filter((k) => k !== "default");
    expect(keys).toEqual([]);
  });

  it("plugin.v2.js's default export shape is {id, setup}, not a Plugin.define(...) call result requiring a runtime import", () => {
    expect(PluginV2).toHaveProperty("id");
    expect(typeof PluginV2.setup).toBe("function");
  });

  it("no src file runtime-imports @opencode/plugin or @opencode-ai/plugin (design.md D1/D7)", () => {
    for (const file of readdirSync(SRC_DIR)) {
      if (!file.endsWith(".js")) continue;
      const source = readFileSync(new URL(file, `file://${SRC_DIR}`), "utf8");
      const hasRuntimeImport = /^\s*import\s.*@opencode(-ai)?\/plugin/m.test(source);
      expect(hasRuntimeImport, `${file} must not have a runtime import of an opencode plugin SDK`).toBe(false);
    }
  });

  it("D1 tripwire: Plugin.define is a verified identity function (test-only import of the devDependency)", async () => {
    const { Plugin } = await import("@opencode/plugin");
    const obj = { id: "x", setup: () => {} };
    expect(Plugin.define(obj)).toBe(obj);
  });
});
