// spec: openspec/specs/tool-output-redaction/spec.md
// spec: openspec/specs/user-message-redaction/spec.md
//
// Layer-2 adapter-conformance suite (design.md D9): drives a shared fixture
// corpus through a fake V1 host and a fake V2 ctx, asserting the two
// adapters produce string-identical redacted text, identical annotations,
// and identical log content — the property that stops the two adapters
// drifting apart. V2-only shape-specific cases (Content[] walk, tool-error
// redaction, output fallback), lifecycle, and invariant cases follow.
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
const STRUCTURED_BRANCHES = [
  { reason: "cycle", create: () => { const branch = []; branch.push(branch); return branch; } },
  {
    reason: "depth",
    create: (secret) => {
      let branch = { note: secret };
      for (let i = 0; i < 128; i += 1) branch = { child: branch };
      return branch;
    },
  },
  { reason: "budget", create: (secret) => `${"x".repeat(200_000)}${secret}` },
];
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
  // spec: openspec/specs/tool-output-redaction/spec.md
  it("V1 metadata depth skips preserve independent redactions", async () => {
    const { client, v1Hooks } = await loadV1();
    const secret = RULE_FIXTURES[0].content;
    let branch = { note: secret };
    for (let i = 0; i < 128; i += 1) branch = { child: branch };
    const leaf = branch;
    const metadata = { before: secret, branch, after: secret };
    await v1Hooks["tool.execute.after"]({ tool: "shell" }, { output: CLEAN_TEXT, metadata });
    expect(metadata.before).toContain("***REDACTED:");
    expect(metadata.after).toContain("***REDACTED:");
    let deepest = leaf;
    for (let i = 0; i < 128; i += 1) deepest = deepest.child;
    expect(deepest.note).toBe(secret);
    const logs = client.app.log.mock.calls.map(([entry]) => entry.body);
    expect(logs.some((entry) => entry.level === "warn" && entry.message.includes("depth"))).toBe(true);
    expect(logs.some((entry) => entry.message.includes("redacted 2"))).toBe(true);
    expect(JSON.stringify(logs)).not.toContain(secret);
  });

  // spec: openspec/specs/tool-output-redaction/spec.md
  it("V1 metadata scanning is isolated from output failures", async () => {
    const { client, v1Hooks } = await loadV1();
    const secret = RULE_FIXTURES[0].content;
    const metadata = { note: secret };
    const output = { get output() { throw new Error(secret); }, metadata };
    await expect(v1Hooks["tool.execute.after"]({ tool: "shell" }, output)).resolves.toBeUndefined();
    expect(metadata.note).toContain("***REDACTED:");
    expect(JSON.stringify(client.app.log.mock.calls)).not.toContain(secret);
  });

  // spec: openspec/specs/tool-output-redaction/spec.md
  it("V1 metadata redacts own prototype keys without changing prototypes", async () => {
    const { v1Hooks } = await loadV1();
    const secret = RULE_FIXTURES[0].content;
    const metadata = JSON.parse(JSON.stringify({ ["__proto__"]: secret, nested: { note: secret } }));
    await v1Hooks["tool.execute.after"]({ tool: "shell" }, { metadata });
    expect(Object.getPrototypeOf(metadata)).toBe(Object.prototype);
    expect(Object.hasOwn(metadata, "__proto__")).toBe(true);
    expect(metadata.__proto__).toContain("***REDACTED:");
    expect(metadata.nested.note).toContain("***REDACTED:");
  });
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
  // spec: openspec/specs/tool-output-redaction/spec.md
  it("Output of an unsuccessful tool invocation IS scanned", async () => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    class ToolError extends Error {}
    const error = Object.assign(new ToolError("tool failed"), { metadata: { note: `meta ${secret}` } });
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
    expect(event.error).toBe(error);
    expect(Object.getPrototypeOf(event.error)).toBe(ToolError.prototype);
    expect(event.error.message).toContain("***REDACTED:");
    expect(event.error.message).not.toContain(secret);
    expect(event.error.metadata.note).toContain("***REDACTED:");
    expect(event.error.metadata.note).not.toContain(secret);
  });

  // spec: openspec/specs/tool-output-redaction/spec.md
  it("Read-only host error fields are preserved while writable siblings are redacted", async () => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const error = {};
    Object.defineProperty(error, "locked", { value: secret, writable: false });
    error.note = secret;
    const event = { tool: "shell", status: "error", error };
    await hooks["execute.after"](event);
    expect(event.error).toBe(error);
    expect(error.locked).toBe(secret);
    expect(error.note).toContain("***REDACTED:");
  });

  // spec: openspec/specs/tool-output-redaction/spec.md
  it.each([() => new Date(0), () => new Map([["key", "value"]]), () => new Error("fixture")])(
    "Non-plain structured values are left untouched", async (create) => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const instance = Object.assign(create(), { note: secret });
      const metadata = { instance, note: secret };
      const event = { tool: "shell", status: "completed", result: { metadata } };
      await hooks["execute.after"](event);
      expect(event.result.metadata.instance).toBe(instance);
      expect(instance.note).toBe(secret);
      expect(event.result.metadata.note).toContain("***REDACTED:");
      expect(metadata.note).toBe(secret);
    },
  );

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

  it.each(["completed", "error", "history"])("Shared graphs cannot exhaust traversal work (%s)", async (status) => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    let graph = {};
    for (let i = 0; i < 14; i += 1) graph = { left: graph, right: graph };
    const value = { note: secret, graph };
    const event = status === "history"
      ? { system: [], messages: [{ role: "assistant", content: [{ type: "tool-call", input: value }] }] }
      : { tool: "shell", status, error: value, result: { metadata: value } };
    const { lines } = await captureStderr(() => hooks[status === "history" ? "context" : "execute.after"](event));
    const scanned = status === "history" ? event.messages[0].content[0].input
      : status === "error" ? event.error : event.result.metadata;
    expect(scanned.note).toContain("***REDACTED:");
    expect(scanned.graph).toBe(graph);
    expect(lines.filter((line) => line.includes("skipped") && line.includes("visits"))).toHaveLength(1);
    expect(lines.join("")).not.toContain(secret);
  });

  it.each(["completed", "error"])("Throwing properties do not suppress readable siblings (%s)", async (status) => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const getter = () => { throw new Error(secret); };
    const sparse = [, secret];
    const value = { sparse };
    Object.defineProperty(value, "unreadable", { get: getter, enumerable: true });
    Object.defineProperty(value, "note", { value: secret, enumerable: false, writable: true });
    const event = { tool: "shell", status, error: value, result: { metadata: value } };
    const { lines } = await captureStderr(() => hooks["execute.after"](event));
    const scanned = status === "error" ? event.error : event.result.metadata;
    expect(scanned.note).toContain("***REDACTED:");
    expect(scanned.sparse[1]).toContain("***REDACTED:");
    expect(Object.getOwnPropertyDescriptor(scanned, "unreadable")).toMatchObject({ get: getter });
    expect(Object.getOwnPropertyDescriptor(scanned, "note").enumerable).toBe(false);
    expect(0 in scanned.sparse).toBe(false);
    expect(lines.join("")).not.toContain(secret);
    if (status === "completed") expect(value.note).toBe(secret);
  });

  it.each(["completed", "error"])("An unusually large structured result does not block indefinitely (%s)", async (status) => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const blob = STRUCTURED_BRANCHES.find((entry) => entry.reason === "budget").create(secret);
    const value = { blob, duplicate: blob, note: `leak=${secret}` };
    const error = Object.assign(new Error("tool failed"), value);
    const event = { tool: "bash", status, error, result: { content: CLEAN_TEXT, metadata: value } };
    const { lines } = await captureStderr(() => hooks["execute.after"](event));
    const scanned = status === "error" ? event.error : event.result.metadata;
    expect(scanned.blob).toBe(blob);
    expect(scanned.duplicate).toBe(blob);
    expect(scanned.note).toContain("***REDACTED:");
    expect(scanned.note).not.toContain(secret);
    expect(lines.filter((line) => line.includes("skipped") && line.includes("budget"))).toHaveLength(1);
    expect(lines.join("")).not.toContain(secret);
    if (status === "error") expect(event.error).toBe(error);
  });

  it.each(STRUCTURED_BRANCHES.filter((entry) => entry.reason !== "budget").flatMap((entry) =>
    ["completed", "error"].map((status) => ({ ...entry, status }))))(
    "Cyclic and deep structured branches are skipped independently ($reason, $status)", async ({ reason, create, status }) => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const branch = create(secret);
      const value = { branch, note: `leak=${secret}` };
      const error = Object.assign(new Error("tool failed"), value);
      const event = { tool: "bash", status, error, result: { content: CLEAN_TEXT, metadata: value } };
      const { lines } = await captureStderr(() => hooks["execute.after"](event));
      const scanned = status === "error" ? event.error : event.result.metadata;
      expect(scanned.branch).toBe(branch);
      expect(scanned.note).toContain("***REDACTED:");
      expect(scanned.note).not.toContain(secret);
      expect(lines.filter((line) => line.includes("skipped") && line.includes(reason))).toHaveLength(1);
      expect(lines.join("")).not.toContain(secret);
      if (status === "error") expect(event.error).toBe(error);
    },
  );
});

// spec: openspec/specs/request-payload-redaction/spec.md
describe("V2-only shape-specific cases — session context/generate/compaction hooks", () => {
  const HOOK_NAMES = ["context", "generate", "compaction", "title"];

  // spec: openspec/specs/request-payload-redaction/spec.md
  it("A title-generation request is redacted", async () => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const event = { system: [{ type: "text", text: secret }], messages: [{ role: "user", content: [{ type: "text", text: secret }] }] };
    await hooks.title(event);
    expect(event.system[0].text).toContain("***REDACTED:");
    expect(event.messages[0].content[0].text).toContain("***REDACTED:");
    expect(JSON.stringify(event)).not.toContain(secret);
  });

  // spec: openspec/specs/request-payload-redaction/spec.md
  it.each(["characters", "visits"])("Structured history budgets are shared across the request", async (limit) => {
    const { hooks } = await loadV2();
    const secret = RULE_FIXTURES[0].content;
    const first = limit === "characters" ? "x".repeat(200_000) : Array(9999).fill(null);
    const original = { type: "tool-result", result: { type: "json", value: { note: secret } } };
    const event = { system: [], messages: [
      { role: "assistant", content: [{ type: "tool-call", input: first }] },
      { role: "tool", content: [original, { type: "tool-call", input: { note: secret } }] },
    ] };
    const { lines } = await captureStderr(() => hooks.context(event));
    expect(event.messages[1].content[0]).toBe(original);
    expect(original.result.value.note).toBe(secret);
    const reason = limit === "characters" ? "budget" : "visits";
    expect(lines.filter((line) => line.includes("skipped") && line.includes(reason))).toHaveLength(1);
    expect(lines.join("")).not.toContain(secret);
    const fresh = { system: [], messages: [{ role: "tool", content: [original] }] };
    await hooks.context(fresh);
    expect(fresh.messages[0].content[0].result.value.note).toContain("***REDACTED:");
  });

  it("setup registers context, generate, and compaction session hooks", async () => {
    const { ctx } = await loadV2();
    for (const name of HOOK_NAMES) {
      expect(ctx.session.hook).toHaveBeenCalledWith(name, expect.any(Function));
    }
  });

  for (const name of HOOK_NAMES) {
    it.each([false, true])(`${name}: Structured history traversal uses observable bounds (string input, oversized=%s)`, async (oversized) => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const input = oversized ? "x".repeat(200_000) + secret : secret;
      const original = { type: "tool-call", input };
      const event = { system: [], messages: [{ role: "assistant", content: [original] }] };
      const { lines } = await captureStderr(() => hooks[name](event));
      const scanned = event.messages[0].content[0];
      if (oversized) {
        expect(scanned).toBe(original);
        expect(lines.some((line) => line.includes("skipped") && line.includes("budget"))).toBe(true);
      } else {
        expect(scanned.input).toContain("***REDACTED:");
        expect(scanned.input).not.toContain(secret);
      }
      expect(original.input).toBe(input);
    });

    it(`${name}: Redacts a secret in a tool-call input or tool-result value (content variant)`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const file = { type: "file", uri: "file:///tmp/fixture", mime: "text/plain" };
      const original = { type: "tool-result", result: { type: "content", value: [{ type: "text", text: secret }, file] } };
      const event = { system: [], messages: [{ role: "tool", content: [original] }] };
      await hooks[name](event);
      const scanned = event.messages[0].content[0];
      expect(scanned.result.value[0].text).toContain("***REDACTED:");
      expect(scanned.result.value[0].text).not.toContain(secret);
      expect(scanned.result.value[1]).toBe(file);
      expect(original.result.value[0].text).toBe(secret);
    });

    it.each(["user", "assistant"])(`${name}: Unknown text-bearing parts retain role-specific fences (%s)`, async (role) => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const original = { type: "future-text", text: `\`\`\`noredact\n${secret}\n\`\`\`\n${secret}` };
      const event = { system: [], messages: [{ role, content: [original, { type: "tool-result", result: null }] }] };
      await hooks[name](event);
      const parts = event.messages[0].content;
      expect(parts[0].text).toContain("***REDACTED:");
      expect(parts[0].text.includes(secret)).toBe(role === "user");
      expect(parts[1].result).toBeNull();
      expect(original.text).toContain(secret);
    });

    it.each(STRUCTURED_BRANCHES.flatMap((entry) => ["tool-call", "tool-result"].map((type) => ({ ...entry, type }))))(
      `${name}: Structured history traversal uses observable bounds ($reason, $type)`, async ({ reason, create, type }) => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const input = { branch: create(secret), duplicate: null, note: `leak=${secret}` };
      input.duplicate = input.branch;
      const event = {
        system: [],
        messages: [{ role: type === "tool-call" ? "assistant" : "tool", content: [
          type === "tool-call"
            ? { type, id: "1", name: "shell", input }
            : { type, id: "1", name: "shell", result: { type: "json", value: input } },
        ] }],
      };
      const { lines } = await captureStderr(() => hooks[name](event));
      const part = event.messages[0].content[0];
      const scanned = type === "tool-call" ? part.input : part.result.value;
      expect(scanned.branch).toBe(input.branch);
      expect(scanned.note).toContain("***REDACTED:");
      expect(scanned.note).not.toContain(secret);
      expect(input.note).toBe(`leak=${secret}`);
      expect(lines.filter((line) => line.includes("skipped") && line.includes(reason))).toHaveLength(1);
      expect(lines.join("")).not.toContain(secret);
    });

    it.each(["system", "message"])(`${name}: A malformed request container does not suppress later messages (%s)`, async (container) => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      const malformed = { type: "text", get text() { throw new Error(secret); } };
      const event = {
        system: container === "system" ? [malformed] : [],
        messages: [
          ...(container === "message" ? [{ role: "assistant", content: [malformed] }] : []),
          { role: "user", content: [{ type: "text", text: `leak=${secret}` }] },
        ],
      };
      const { lines } = await captureStderr(() => hooks[name](event));
      expect(event.messages.at(-1).content[0].text).toContain("***REDACTED:");
      expect(event.messages.at(-1).content[0].text).not.toContain(secret);
      expect(lines.some((line) => line.includes("[error]"))).toBe(true);
      expect(lines.join("")).not.toContain(secret);
    });

    it(`${name}: Signed tool-call metadata and ordering are preserved`, async () => {
      const { hooks } = await loadV2();
      const secret = RULE_FIXTURES[0].content;
      // OpenCode 2.0.26's Gemini decoder stores each part's thoughtSignature
      // in providerMetadata independently from functionCall.args -> input.
      const providerMetadata = { google: { thoughtSignature: "signed-call-proof" } };
      const signed = { type: "tool-call", id: "signed", name: "shell", input: { cmd: secret }, providerMetadata };
      const sibling = { type: "tool-call", id: "parallel", name: "read", input: { path: secret } };
      const originals = [signed, sibling];
      const event = { system: [], messages: [{ role: "assistant", content: [...originals] }] };
      await hooks[name](event);
      const parts = event.messages[0].content;
      expect(parts.map(({ id, name }) => ({ id, name }))).toEqual([
        { id: "signed", name: "shell" }, { id: "parallel", name: "read" },
      ]);
      expect(parts[0].providerMetadata).toBe(providerMetadata);
      expect(parts[0].providerMetadata.google.thoughtSignature).toBe("signed-call-proof");
      expect(parts[1]).not.toHaveProperty("providerMetadata");
      expect(parts[0].input.cmd).toContain("***REDACTED:");
      expect(parts[1].input.path).toContain("***REDACTED:");
      expect(signed.input.cmd).toBe(secret);
      expect(sibling.input.path).toBe(secret);
      expect(parts[0]).not.toBe(signed);
      expect(parts[1]).not.toBe(sibling);
    });

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

    // spec: openspec/specs/request-payload-redaction/spec.md
    it("Signed reasoning is left untouched", async () => {
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

    // spec: openspec/specs/request-payload-redaction/spec.md
    it("No text-bearing part to carry the annotation", async () => {
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
      // Freezing shared parts turns any accidental in-place mutation into a
      // strict-mode failure while allowing request-array slot replacement.
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
  const hookNames = ["context", "generate", "compaction", "title"];
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
