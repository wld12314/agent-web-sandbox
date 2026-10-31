// _test_apply.mjs — load-time regression test.
//
// Guards the one failure mode the pure tests cannot see: `apply()` throwing
// while registering the tool. A bad `output.schema` literal does not surface
// until `defineTool()` compiles it, so a suite that only imports
// `sanitize.js` / `canary-watch.js` stays green on a plugin that cannot load.
//
// Run: node _test_apply.mjs
//
// Requires the host packages (`@deepseek-ai/schemastery`, `@deepseek-ai/dsh-tools`)
// to be resolvable. They are peerDependencies supplied by the host runtime,
// so outside a profile this test reports a skip instead of a failure.

let pass = 0;
let fail = 0;
function check(label, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  ok  ${label}`);
  } else {
    fail++;
    console.error(`FAIL  ${label}${detail === undefined ? "" : ` — ${detail}`}`);
  }
}

// --- part 1: source-level guard, needs no host packages --------------------
//
// dsh-tools rejects `required: false` outright when it compiles a value
// schema: "schema.<path>.required must be true when present". The key is
// either absent (optional) or literally `true`. That rule lives in the host,
// so a source scan is the only check that works without the host installed —
// and it catches the exact regression that kept apply() from ever running.

import { readFileSync } from "node:fs";

const source = readFileSync(new URL("./lib/index.js", import.meta.url), "utf8");
const requiredValues = [...source.matchAll(/\brequired:\s*([^,\n}]+)/g)].map((m) => m[1].trim());

check(
  "no `required: false` in lib/index.js",
  !requiredValues.some((value) => value === "false"),
  requiredValues.filter((value) => value === "false").join(",")
);
check(
  "every `required:` is a boolean literal",
  requiredValues.every((value) => value === "true" || value === "false"),
  requiredValues.filter((value) => value !== "true" && value !== "false").join(",")
);
check("schema actually declares required fields", requiredValues.length > 0);

// --- part 2: real load, needs the host peers -------------------------------
let mod;
try {
  mod = await import("./lib/index.js");
} catch (error) {
  const code = error?.code;
  if (code === "ERR_MODULE_NOT_FOUND") {
    console.log("skip: host peer dependencies not installed next to this package");
    console.log(`      (${error.message.split("\n")[0]})`);
    console.log(`      install this plugin into a DSH profile, then run this test there`);
    console.log(`\n${pass} passed, ${fail} failed (load checks skipped)`);
    if (fail > 0) process.exit(1);
    process.exit(0);
  }
  throw error;
}

check("module exposes apply", typeof mod.apply === "function");
check("module exposes Config", typeof mod.Config === "function");
check("module name is web-sandbox", mod.name === "web-sandbox");
check(
  "inject requests tools/web/systemPrompt",
  Array.isArray(mod.inject) &&
    ["tools", "web", "systemPrompt"].every((n) => mod.inject.includes(n)),
  JSON.stringify(mod.inject)
);

// Defaults resolved through the real schemastery schema.
const config = new mod.Config({});
check("Config default enabled", config.enabled === true);
check("Config default watchCanaryEcho", config.watchCanaryEcho === true);
check("Config default disablePlainWebFetch", config.disablePlainWebFetch === false);

// --- a ctx stub that records what the plugin touches -----------------------
function makeCtx() {
  const recorded = { tools: [], sections: [], events: [], guards: 0 };
  let tool;
  const disposer = () => {};
  const ctx = {
    on(event) {
      recorded.events.push(event);
      return disposer;
    },
    effect() {
      return disposer;
    },
    tools: {
      register(definition) {
        tool = definition;
        recorded.tools.push(definition);
        return disposer;
      },
      get(name) {
        return tool !== undefined && (tool.name ?? tool.title) === name ? tool : undefined;
      },
      guard() {
        recorded.guards++;
        return disposer;
      }
    },
    systemPrompt: {
      section(section) {
        recorded.sections.push(section);
        return disposer;
      },
      getSectionOrder() {
        return 100;
      }
    },
    web: {
      async fetch() {
        throw new Error("not stubbed for the apply test");
      }
    },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    get() {
      return undefined;
    }
  };
  return { ctx, recorded };
}

// --- the regression: apply() must not throw --------------------------------
const { ctx, recorded } = makeCtx();
let applyError;
try {
  await mod.apply(ctx, config);
} catch (error) {
  applyError = error;
}
check("apply() resolves without throwing", applyError === undefined, applyError?.message);

if (applyError === undefined) {
  check("registers exactly one tool", recorded.tools.length === 1, String(recorded.tools.length));
  check("registered tool is web_fetch_safe", recorded.tools[0]?.name === "web_fetch_safe");
  check("tool exposes execute()", typeof recorded.tools[0]?.execute === "function");
  check("tool has a timeout", typeof recorded.tools[0]?.timeoutMs === "number");
  check("tool declares an output schema", recorded.tools[0]?.output?.schema !== undefined);
  check("adds the web_fetch_safe prompt section", recorded.sections.some((s) => s.name === "tool:web_fetch_safe"));
  check(
    "wires the canary watchdog on session/event",
    recorded.events.includes("session/event"),
    recorded.events.join(",")
  );
  check("registers a dispose handler", recorded.events.includes("dispose"));
  check("plain web_fetch not guarded by default", recorded.guards === 0);
}

// --- disablePlainWebFetch installs the guard --------------------------------
const optIn = new mod.Config({ disablePlainWebFetch: true });
const second = makeCtx();
let optInError;
try {
  await mod.apply(second.ctx, optIn);
} catch (error) {
  optInError = error;
}
check("apply() with disablePlainWebFetch resolves", optInError === undefined, optInError?.message);
check("disablePlainWebFetch installs a tool guard", second.recorded.guards === 1);

// --- enabled:false is a clean no-op ---------------------------------------
const disabled = new mod.Config({ enabled: false });
const third = makeCtx();
let disabledError;
try {
  await mod.apply(third.ctx, disabled);
} catch (error) {
  disabledError = error;
}
check("apply() with enabled:false resolves", disabledError === undefined, disabledError?.message);
check("enabled:false registers nothing", third.recorded.tools.length === 0);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
