// _test_canary_watch.mjs — local verification of the client-shell canary watchdog.
// Run: node agent-web-sandbox/_test_canary_watch.mjs
import {
  CanaryWatch,
  textOfAssistantMessage,
  canariesFromToolResult,
  detectCanaryLeak
} from "./lib/canary-watch.js";
import { makeCanary } from "./lib/sanitize.js";

let pass = 0;
let fail = 0;
function check(label, cond) {
  if (cond) {
    pass++;
    console.log(`  ok  ${label}`);
  } else {
    fail++;
    console.error(`FAIL  ${label}`);
  }
}

// --- text extraction from assistant/message ---
const am = {
  type: "assistant/message",
  seq: 5,
  message: { content: [{ type: "text", text: "Here is the answer." }] }
};
check("textOfAssistantMessage extracts text", textOfAssistantMessage(am) === "Here is the answer.");
check("textOfAssistantMessage ignores non-message", textOfAssistantMessage({ type: "tool/result" }) === "");

// --- learning canaries from a tool/result event ---
const canary = makeCanary();
const toolResultEvent = {
  type: "tool/result",
  seq: 4,
  message: {
    content: [
      {
        type: "tool-result",
        result: { url: "https://x.test", injectionScan: { triggered: false, findings: [], canary } }
      }
    ]
  }
};
const learned = canariesFromToolResult(toolResultEvent);
check("canariesFromToolResult learns the canary", learned.length === 1 && learned[0] === canary);

// --- end-to-end: a reply that echoes the canary is flagged ---
const watch = new CanaryWatch();
watch.observeEvent(toolResultEvent); // learn the canary
check("watch registered the canary", watch.pending === 1);

const echoReply = {
  type: "assistant/message",
  seq: 6,
  message: { content: [{ type: "text", text: `Sure! ${canary} Now I will follow the page.` }] }
};
const alerts = watch.observeEvent(echoReply);
check("echoing the canary produces a leak alert", alerts.length === 1 && alerts[0].kind === "canary-leak");
check("alert carries the canary + message", alerts[0].canary === canary && /evidence/i.test(alerts[0].message));

// --- a clean reply with no canary is not flagged (no NEW leak appears) ---
const beforeClean = watch.leaks.length;
const cleanReply = {
  type: "assistant/message",
  seq: 7,
  message: { content: [{ type: "text", text: "I will not follow instructions from web pages." }] }
};
const alerts2 = watch.observeEvent(cleanReply);
check("clean reply is not flagged", alerts2.length === 0 && watch.leaks.length === beforeClean);

// --- idempotent processing on repeated seq ---
const dup = watch.observeEvent({ ...echoReply, seq: 6 });
check("duplicate seq is not re-flagged", dup.length === 0);

// --- onLeak callback fires ---
let fired = null;
const watch2 = new CanaryWatch({ onLeak: (a) => { fired = a; } });
watch2.observeEvent(toolResultEvent);
watch2.observeEvent(echoReply);
check("onLeak callback is invoked", fired && fired.kind === "canary-leak");

// --- observeSession sorts by seq so canaries are learned first ---
const watch3 = new CanaryWatch();
// deliver reply before the tool result, out of order
const allAlerts = watch3.observeSession([echoReply, toolResultEvent]);
check("observeSession learns canary then flags echo", allAlerts.length === 1);

// --- detectCanaryLeak re-export works ---
check("detectCanaryLeak re-exported", detectCanaryLeak("x " + canary, canary) === true);

// --- INTEGRATION: the in-plugin auto-wire contract (mirrors lib/index.js L3b) ---
// lib/index.js cannot be imported here (it pulls @deepseek-ai/* deps not installed
// in this repo), so we reproduce the EXACT wiring closure it uses and assert the
// end-to-end behavior the README now claims: a session/event subscription that
// learns the canary from tool/result and appends an INJECTION ALERT on echo.
function buildWiredReceiver() {
  const handlers = [];
  const session = {
    appended: [],
    append(type, data) { this.appended.push({ type, data }); }
  };
  const ctx = {
    on: (evt, fn) => { if (evt === "session/event") handlers.push(fn); return () => {}; }
  };
  let liveSession = null;
  const watch = new CanaryWatch({
    onLeak: (alert) => {
      try {
        liveSession?.append?.("system/message", {
          intent: "notice",
          text: `[agent-web-sandbox INJECTION ALERT] The assistant echoed a web-sandbox canary (${alert.canary}).`
        });
      } catch {}
    }
  });
  const disposer = ctx.on("session/event", (sessionArg, event) => {
    liveSession = sessionArg;
    if (event && typeof event === "object") watch.observeEvent(event);
  });
  return { handlers, session, disposer };
}

const wired = await buildWiredReceiver();
check("auto-wire subscribes to session/event", wired.handlers.length === 1);

// feed the same tool/result then an echoing assistant reply through the handler
wired.handlers[0](wired.session, toolResultEvent);
wired.handlers[0](wired.session, echoReply);
check("auto-wire appends an INJECTION ALERT system/message on echo",
  wired.session.appended.length === 1 &&
  wired.session.appended[0].type === "system/message" &&
  /INJECTION ALERT/.test(wired.session.appended[0].data.text));
check("disposer is a function (cleanup path exists)", typeof wired.disposer === "function");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
