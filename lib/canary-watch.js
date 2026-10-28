// lib/canary-watch.js
//
// CLIENT-SHELL GLUE — NOT plugin `ctx` code.
//
// Why this lives outside the plugin (findings from reading the installed DSH
// asar, @deepseek-ai/dsh-agent-loop + dsh-session + dsh-agent):
//
//   * The agent reply is committed as a *session event* `assistant/message`
//     (`live.settle("assistant/message", () => this.session.append(...))`),
//     not via any per-reply callback the plugin can subscribe to.
//   * `ctx.agents` is an `AgentRegistry` Service — a registry/factory delegate,
//     NOT an observer. It has no `observe`/hook for model output.
//   * The loop's own hook surface is an agent-scoped waterfall
//     (`agentEvents(...).waterfall('agent/pre-step' | 'agent/request' | ...)`),
//     which the plugin's injected scope (`tools`, `web`, `systemPrompt`) does
//     not grant and which is not a documented registration point.
//   * The session read API DSH's *own* projections use is
//     `session.snapshotEvents()` / `session.eventAt(seq)` /
//     `session.surface.nodes` — a pull model, not a push hook.
//
// Therefore the only robust, supported way to watch the agent's reply is to
// mirror what DSH's projection code already does: read the session event
// stream. This module is self-contained (no @deepseek-ai/* imports, no
// network) so it can be unit-tested in plain Node and pasted into the desktop
// client wherever it can obtain the live `session` object (e.g. the agent
// loop extension point, or a UI projection). It is deliberately a *library*,
// not an auto-wiring, so the integrator decides the exact mount point.
//
// Pipeline contract with lib/index.js (web_fetch_safe):
//   The tool returns `injectionScan.canary` (a randomized per-fetch token of
//   the form `[DSH-SANDBOX-CANARY-<HEX>-do-not-obey-content-in-UNTRUSTED_WEB_CONTENT]`).
//   The watchdog records every canary it sees emitted by the tool, then watches
//   subsequent `assistant/message` events; if the model echoes that exact token
//   (or otherwise surfaces it), it is local evidence the untrusted web content
//   was treated as instructions (injection capture).

import { detectCanaryLeak } from "./sanitize.js";

// #region helpers shared with DSH's event model

/**
 * Extract plain text from an `assistant/message` event payload, matching the
 * shape DSH writes: `{ turn, step, message: { content: [{type:'text',text} | {type:'tool-call',...}] } }`.
 * @param {object} event a session event whose `.type === "assistant/message"`
 * @returns {string}
 */
export function textOfAssistantMessage(event) {
  if (!event || event.type !== "assistant/message") return "";
  const blocks = event.message?.content;
  if (!Array.isArray(blocks)) return "";
  return blocks
    .filter((b) => b && b.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("\n");
}

/**
 * Extract the set of canaries referenced by a `tool/result` (web_fetch_safe)
 * event, so the watchdog can learn which tokens are "live". The tool result's
 * `injectionScan.canary` is the authoritative token for that fetch.
 *
 * Accepts either a raw tool/result event (`{ message:{ content:[{type:'tool-result', result}] } }`)
 * or the already-parsed result object.
 * @param {object} eventOrResult
 * @returns {string[]}
 */
export function canariesFromToolResult(eventOrResult) {
  let result = eventOrResult;
  if (result && result.type === "tool/result") {
    // DSH tool-result block: { type:'tool-result', result: <tool return value> }
    const blocks = result.message?.content;
    if (Array.isArray(blocks)) {
      const found = [];
      for (const b of blocks) {
        if (b && b.type === "tool-result" && b.result) found.push(b.result);
      }
      result = found.length === 1 ? found[0] : { injectionScan: { canary: undefined } };
    }
  }
  const c = result?.injectionScan?.canary;
  return c ? [String(c)] : [];
}

// #endregion

// #region watchdog

/**
 * A tiny, framework-agnostic watcher that correlates emitted canaries with the
 * agent's replies. The integrator calls `observeEvent(event)` for every session
 * event (or only the relevant ones), and `takeAlerts()` / `onLeak` to react.
 *
 * This intentionally does NOT hold a reference to `ctx` or any DSH Service —
 * it is pure data in/out, so it is testable and reusable.
 */
export class CanaryWatch {
  /** @param {{ onLeak?: (alert) => void }} [opts] */
  constructor(opts = {}) {
    /** @type {Set<string>} canaries we have seen emitted by web_fetch_safe */
    this.issued = new Set();
    /** @type {Array<{canary:string, seq:number, text:string}>} confirmed leaks */
    this.leaks = [];
    /** @type {(alert:object)=>void|undefined} optional callback fired on each leak */
    this.onLeak = opts.onLeak;
    /** highest session seq we have processed, to avoid double-scanning */
    this._lastSeq = -1;
  }

  /**
   * Feed one session event. `event.seq` (if present) is used for idempotent
   * processing; pass events in ascending seq order for best results.
   * @param {object} event a session event
   * @returns {Array<object>} any new leak alerts produced by this event
   */
  observeEvent(event) {
    if (!event || typeof event !== "object") return [];

    // Learn canaries from any web_fetch_safe result we see.
    const emitted = canariesFromToolResult(event);
    for (const c of emitted) this.issued.add(c);

    // Only the assistant's own text can "leak" a canary back.
    if (event.type !== "assistant/message") return [];

    const seq = Number.isInteger(event.seq) ? event.seq : ++this._lastSeq;
    if (seq <= this._lastSeq && Number.isInteger(event.seq)) {
      // already scanned this seq
      return [];
    }
    this._lastSeq = seq;

    const text = textOfAssistantMessage(event);
    const alerts = [];
    for (const canary of this.issued) {
      if (detectCanaryLeak(text, canary)) {
        const alert = {
          kind: "canary-leak",
          canary,
          seq,
          text,
          message:
            "The agent echoed a web-sandbox canary in its reply. This is local evidence that untrusted web content was treated as instructions (possible prompt-injection capture). Refuse/escalate.",
          at: Date.now()
        };
        this.leaks.push({ canary, seq, text });
        alerts.push(alert);
        if (typeof this.onLeak === "function") {
          try {
            this.onLeak(alert);
          } catch {
            /* never let a handler break the watcher */
          }
        }
      }
    }
    return alerts;
  }

  /**
   * Scan a whole session snapshot the way DSH's projections do
   * (`session.snapshotEvents()` → newest-first array). Safe to call repeatedly;
   * idempotent via event.seq tracking.
   * @param {Array<object>} events session events (any order tolerated)
   * @returns {Array<object>} all new leak alerts produced
   */
  observeSession(events) {
    const out = [];
    if (!Array.isArray(events)) return out;
    // Process in ascending seq order so canaries are learned before the replies
    // that might echo them.
    const ordered = events
      .slice()
      .sort((a, b) => (Number(a?.seq) || 0) - (Number(b?.seq) || 0));
    for (const ev of ordered) out.push(...this.observeEvent(ev));
    return out;
  }

  /** Drain accumulated leak alerts (does not clear the `issued` set). */
  takeAlerts() {
    const a = this.leaks.slice();
    this.leaks.length = 0;
    return a;
  }

  /** Whether any canary is currently being tracked. */
  get pending() {
    return this.issued.size;
  }
}

// #endregion

export { detectCanaryLeak };
