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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
