/**
 * langfuse-tracer — OpenClaw plugin (v4)
 *
 * Full observability: agent traces, LLM generations, and tool call spans
 * all reported to Langfuse via the REST ingestion API.
 *
 * Trace hierarchy (aligned with langfuse-js SDK v4 observation model):
 *
 *   Trace (openclaw-session)                   ← one per sessionKey, reused
 *     └─ Span[agent] (agent:<agentId>)         ← one per agent turn
 *          ├─ Generation (llm)                 ← LLM call
 *          ├─ Span[tool] (tool:web_search)     ← tool calls
 *          └─ Span[agent] (agent:<subAgentId>) ← sub-agent (nested)
 *               ├─ Generation (llm)
 *               └─ Span[tool] (tool:read_file)
 *
 * Upload pipeline (inspired by langfuse-js SDK):
 *   - No hard truncation: data is sent in full unless a single event > 3.5 MB
 *   - Automatic batch splitting when total payload > 3 MB
 *   - Retry with exponential backoff on 408 / 429 / 5xx (max 2 retries)
 *   - Respects Retry-After / X-RateLimit-Reset headers
 *
 * Hooks used:
 *   - before_agent_start → create session trace + agent span
 *   - llm_input          → capture LLM request
 *   - llm_output         → capture LLM response
 *   - before_tool_call   → capture tool invocation input
 *   - after_tool_call    → capture tool invocation output
 *   - agent_end          → flush the complete agent span to Langfuse
 *
 * Required env vars:
 *   LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_BASE_URL
 *
 * Optional env vars:
 *   LANGFUSE_RELEASE, LANGFUSE_ENVIRONMENT
 */

// ── Tracking modules ────────────────────────────────────────────────────────

import { loadConfig } from "./config.js";
import {
  getOrCreateAgentId,
  sessionId as genSessionId,
  turnId as genTurnId,
  actionId as genActionId,
} from "./id-generator.js";
import { DataLineageTracker } from "./data-lineage.js";
import { TaintEngine } from "./taint-engine.js";
import { RiskScorer } from "./risk-scorer.js";
import { ActionRecordBuilder } from "./action-record.js";
import { BeamIntervenor } from "./beam-intervention.js";

// ── Constants ───────────────────────────────────────────────────────────────

const PLUGIN_VERSION = "6.0.0";
const SDK_NAME = "openclaw-langfuse-tracer";

const MAX_BATCH_BYTES = 3 * 1024 * 1024;
const MAX_SINGLE_FIELD_BYTES = 1_000_000;
const INITIAL_RETRY_DELAY = 1000;
const MAX_RETRY_DELAY = 60_000;
const MAX_RETRIES = 2;
const JITTER_FACTOR = 0.2;
const FETCH_TIMEOUT_MS = 30_000;
const MAX_SESSIONS = 500;
const MAX_TURNS = 1000;
const MAX_RETRY_QUEUE = 5000;        // max events in the retry queue
const RETRY_QUEUE_INTERVAL = 60_000; // retry failed events every 60s
const SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

// ── Helpers ─────────────────────────────────────────────────────────────────

function randomId() {
  return crypto.randomUUID();
}

function nowISO() {
  return new Date().toISOString();
}

function safeStringify(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/** setTimeout with .unref() — prevents Node.js from staying alive just for our timers */
function safeSetTimeout(fn, timeout) {
  const t = setTimeout(fn, timeout);
  if (typeof t?.unref === "function") t.unref();
  return t;
}

/** Promise-based sleep using unref'd timer */
function sleep(ms) {
  return new Promise((resolve) => safeSetTimeout(resolve, ms));
}

function clean(obj) {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(clean);
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) out[k] = clean(v);
  }
  return out;
}

function compact(arr) {
  return arr.filter(Boolean);
}

// ── Retry logic (modeled after langfuse-js requestWithRetries) ──────────────

function addJitter(delay) {
  return delay * (1 + (Math.random() - 0.5) * JITTER_FACTOR);
}

function getRetryDelay(response, attempt) {
  const retryAfter = response.headers.get("Retry-After");
  if (retryAfter) {
    const seconds = parseInt(retryAfter, 10);
    if (!isNaN(seconds) && seconds > 0) {
      return Math.min(seconds * 1000, MAX_RETRY_DELAY);
    }
    const date = new Date(retryAfter);
    if (!isNaN(date.getTime())) {
      const delay = date.getTime() - Date.now();
      if (delay > 0) return Math.min(delay, MAX_RETRY_DELAY);
    }
  }
  const rateLimitReset = response.headers.get("X-RateLimit-Reset");
  if (rateLimitReset) {
    const resetTime = parseInt(rateLimitReset, 10);
    if (!isNaN(resetTime)) {
      const delay = resetTime * 1000 - Date.now();
      if (delay > 0) return Math.min(delay, MAX_RETRY_DELAY) * (1 + Math.random() * JITTER_FACTOR);
    }
  }
  return addJitter(Math.min(INITIAL_RETRY_DELAY * Math.pow(2, attempt), MAX_RETRY_DELAY));
}

function isRetryable(status) {
  return status === 408 || status === 429 || status >= 500;
}

/**
 * Fetch with timeout + full retry on both network errors and retryable HTTP status.
 *
 * Retry triggers:
 *   - Network errors: connection refused, DNS failure, timeout (AbortError), ECONNRESET, etc.
 *   - HTTP status: 408 (timeout), 429 (rate limit), 5xx (server error)
 *
 * Backoff: exponential with jitter, respects Retry-After / X-RateLimit-Reset headers.
 */
async function fetchWithRetry(url, fetchOptions, logger) {
  let lastError = null;
  let response = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    // On retry, compute delay based on previous response or network error
    if (attempt > 0) {
      const delay = response
        ? getRetryDelay(response, attempt - 1)
        : addJitter(Math.min(INITIAL_RETRY_DELAY * Math.pow(2, attempt - 1), MAX_RETRY_DELAY));
      const reason = response
        ? `HTTP ${response.status}`
        : String(lastError);
      logger.warn(
        `[langfuse-tracer] Retry ${attempt}/${MAX_RETRIES} in ${Math.round(delay)}ms (${reason})`
      );
      await sleep(delay);
    }

    // Reset for this attempt
    lastError = null;
    response = null;

    try {
      const controller = new AbortController();
      const timeoutId = safeSetTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        response = await fetch(url, { ...fetchOptions, signal: controller.signal });
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (err) {
      lastError = err;
      // Network error → will retry on next iteration
      continue;
    }

    // Got a response — check if it's retryable
    if (!isRetryable(response.status)) {
      return response; // success or non-retryable error (4xx) — done
    }
    // retryable status → loop continues
  }

  // All attempts exhausted
  if (lastError) {
    logger.warn(`[langfuse-tracer] All ${MAX_RETRIES + 1} attempts failed (network): ${String(lastError)}`);
  } else if (response) {
    logger.warn(`[langfuse-tracer] All ${MAX_RETRIES + 1} attempts failed (HTTP ${response.status})`);
  }
  return response; // may be null (network error) or the last retryable response
}

// ── Batch splitting ─────────────────────────────────────────────────────────

function truncateField(value, maxBytes) {
  if (typeof value !== "string" || value.length <= maxBytes) return value;
  return value.slice(0, maxBytes) + "\n...[truncated]";
}

function shrinkEventIfNeeded(event, logger) {
  const size = JSON.stringify(event).length;
  if (size <= MAX_BATCH_BYTES) return event;
  logger.warn(
    `[langfuse-tracer] Single event "${event.type}" is ${(size / 1024 / 1024).toFixed(1)} MB — truncating input/output`
  );
  const copy = { ...event, body: { ...event.body } };
  if (typeof copy.body.input === "string") {
    copy.body.input = truncateField(copy.body.input, MAX_SINGLE_FIELD_BYTES);
  } else if (copy.body.input != null && typeof copy.body.input === "object") {
    copy.body.input = truncateField(JSON.stringify(copy.body.input), MAX_SINGLE_FIELD_BYTES);
  }
  if (typeof copy.body.output === "string") {
    copy.body.output = truncateField(copy.body.output, MAX_SINGLE_FIELD_BYTES);
  }
  return copy;
}

/**
 * Split events into sub-batches each under MAX_BATCH_BYTES.
 * Optimized: serialize each event once and reuse the cached JSON for size math.
 */
function splitBatch(events, logger) {
  const cleaned = events.map(clean);

  // Pre-serialize each event once — reuse for both size calc and final payload
  const serialized = cleaned.map((e, i) => {
    let json = JSON.stringify(e);
    if (json.length > MAX_BATCH_BYTES) {
      const shrunk = clean(shrinkEventIfNeeded(events[i], logger));
      json = JSON.stringify(shrunk);
      cleaned[i] = shrunk;
    }
    return json;
  });

  // Fast path: estimate total size without building full payload string
  // '{"batch":[' + events joined by ',' + ']}'  = 11 + commas + events
  const totalSize = 11 + serialized.reduce((sum, s) => sum + s.length, 0) + Math.max(0, serialized.length - 1);
  if (totalSize <= MAX_BATCH_BYTES) {
    return [cleaned];
  }

  logger.info(
    `[langfuse-tracer] Batch is ${(totalSize / 1024 / 1024).toFixed(1)} MB — splitting`
  );

  const batches = [];
  let currentBatch = [];
  let currentSize = 11; // '{"batch":[]}'.length minus the closing which we account for

  for (let i = 0; i < cleaned.length; i++) {
    const addedSize = serialized[i].length + (currentBatch.length > 0 ? 1 : 0);
    if (currentSize + addedSize > MAX_BATCH_BYTES && currentBatch.length > 0) {
      batches.push(currentBatch);
      currentBatch = [];
      currentSize = 11;
    }
    currentBatch.push(cleaned[i]);
    currentSize += addedSize;
  }
  if (currentBatch.length > 0) batches.push(currentBatch);
  return batches;
}

/**
 * Post events to Langfuse. Returns an array of events that failed to send
 * (after all retries exhausted) so the caller can queue them for later.
 */
async function postBatch(baseUrl, authHeader, events, logger) {
  const batches = splitBatch(events, logger);
  const url = `${baseUrl}/api/public/ingestion`;
  const baseHeaders = {
    Authorization: authHeader,
    "Content-Type": "application/json",
    "X-Langfuse-Sdk-Name": SDK_NAME,
    "X-Langfuse-Sdk-Version": PLUGIN_VERSION,
  };

  // Each concurrent batch collects its own failures, then merge — avoids push races
  const results = await Promise.all(batches.map(async (batch) => {
    const body = JSON.stringify({ batch });
    try {
      const response = await fetchWithRetry(url, { method: "POST", headers: baseHeaders, body }, logger);
      if (!response) {
        // Total network failure after all retries
        return batch;
      }
      if (!response.ok) {
        const text = await response.text().catch(() => "");
        if (isRetryable(response.status)) {
          logger.warn(
            `[langfuse-tracer] Ingestion failed ${response.status} (retryable, ${batch.length} events queued): ${text.slice(0, 300)}`
          );
          return batch;
        }
        // Non-retryable 4xx — log details so data loss is diagnosable
        logger.warn(
          `[langfuse-tracer] Ingestion rejected ${response.status} (${batch.length} events DROPPED — non-retryable): ${text.slice(0, 500)}`
        );
        const eventSummary = batch.map((e) => `${e.type}:${e.body?.id?.slice(0, 12) ?? "?"}`).join(", ");
        logger.warn(`[langfuse-tracer] Dropped events: [${eventSummary}]`);
      }
      return [];
    } catch (err) {
      // Unexpected error in this batch — preserve events for retry
      logger.warn(`[langfuse-tracer] postBatch unexpected error (${batch.length} events preserved): ${String(err)}`);
      return batch;
    }
  }));

  // Flatten per-batch failure arrays into one
  return results.flat();
}

// ── Session state (shared traceId per session) ──────────────────────────────

/**
 * One per sessionKey. Holds a shared traceId so all agent turns and
 * sub-agents in the same conversation appear under a single Langfuse trace.
 *
 * activeAgentStack tracks nesting: when a before_agent_start fires while
 * another agent is already active, the new agent is a sub-agent.
 */
class SessionState {
  constructor(sessionKey) {
    this.traceId = randomId();
    this.sessionKey = sessionKey;
    this.traceCreated = false;
    this.lastActiveMs = Date.now();
    /** @type {string[]} stack of turnKeys for nesting detection */
    this.activeAgentStack = [];
    // ── Tracking IDs ──
    this.trackingSessionId = genSessionId(); // ses_YYYYMMDDTHHMMSS_random
  }

  touch() {
    this.lastActiveMs = Date.now();
  }
}

// ── Per-agent-turn state ────────────────────────────────────────────────────

/**
 * Accumulates observations for a single agent turn before flushing.
 *
 * Langfuse hierarchy (per turn):
 *   Span[agent] (agent:<agentId>)
 *     ├─ Generation (llm)
 *     ├─ Span[tool] (tool:<name>)
 *     └─ Span[agent] (sub-agent)  ← nested via parentAgentSpanId
 */
class TurnState {
  /**
   * @param {string} traceId       - shared from SessionState
   * @param {string|null} parentAgentSpanId - parent agent's spanId (null for root)
   */
  constructor(traceId, parentAgentSpanId) {
    this.traceId = traceId;
    this.agentSpanId = randomId();
    this.parentAgentSpanId = parentAgentSpanId;
    this.startedAt = Date.now();
    this.prompt = "";
    this.agentId = null;
    this.llm = null;
    /** @type {Map<string, object>} */
    this.toolSpans = new Map();
    // ── Tracking IDs ──
    this.trackingAgentId = null;        // agt_... (persistent)
    this.trackingTurnId = genTurnId();  // trn_YYYYMMDDTHHMMSS_random
    this.trackingSessionId = null;      // copied from SessionState
    this.parentTrackingAgentId = null;  // parent agent's tracking ID (cross-agent)
    this.parentTrackingActionId = null; // parent action's tracking ID (cross-agent)
    /** @type {string[]} data_ids active in current turn context */
    this.activeDataIds = [];
    /** @type {object[]} action records accumulated during this turn */
    this.actionRecords = [];
    /** @type {string|null} LLM inference action_id */
    this.llmActionId = null;
    /** @type {string[]} data_ids produced by LLM output */
    this.llmOutputDataIds = [];
    /** @type {string|null} data_id for user prompt input */
    this.promptDataId = null;
  }
}

// ── Plugin entry ────────────────────────────────────────────────────────────

export function register(api) {
  const publicKey = process.env.LANGFUSE_PUBLIC_KEY?.trim();
  const secretKey = process.env.LANGFUSE_SECRET_KEY?.trim();
  const baseUrl = (
    process.env.LANGFUSE_BASE_URL?.trim() ?? "http://172.21.0.1:3050"
  ).replace(/\/$/, "");

  if (!publicKey || !secretKey) {
    api.logger.info(
      "[langfuse-tracer] LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY not set — tracing disabled"
    );
    return;
  }

  const authHeader =
    "Basic " + Buffer.from(`${publicKey}:${secretKey}`).toString("base64");
  const release = process.env.LANGFUSE_RELEASE?.trim() || undefined;
  const environment = process.env.LANGFUSE_ENVIRONMENT?.trim() || undefined;

  api.logger.info(`[langfuse-tracer] Langfuse tracing enabled → ${baseUrl}`);

  // ── Initialize tracking subsystem ─────────────────────────────────────
  const trackingConfig = loadConfig(api.config?.tracking ?? {});
  const lineageTracker = new DataLineageTracker();
  const taintEngine = new TaintEngine(lineageTracker, trackingConfig);
  const riskScorer = new RiskScorer(taintEngine, trackingConfig);
  const beamIntervenor = new BeamIntervenor(trackingConfig);
  api.logger.info(
    `[langfuse-tracer] Tracking subsystem initialized (mode: ${trackingConfig.mode}, ` +
    `beam threshold: ${trackingConfig.risk.beamThreshold})`
  );

  /** @type {Map<string, SessionState>} sessionKey → SessionState */
  const sessions = new Map();
  /** @type {Map<string, TurnState>} turnKey → TurnState */
  const turns = new Map();
  /** @type {Set<Promise<void>>} in-flight upload promises */
  const pendingFlushes = new Set();

  /** Evict stale sessions and orphaned turns to prevent memory leaks */
  function evictStale() {
    const now = Date.now();
    for (const [key, session] of sessions) {
      if (now - session.lastActiveMs > SESSION_TTL_MS && session.activeAgentStack.length === 0) {
        sessions.delete(key);
      }
    }
    // Hard cap: if sessions still exceed limit, drop oldest
    if (sessions.size > MAX_SESSIONS) {
      const sorted = [...sessions.entries()].sort((a, b) => a[1].lastActiveMs - b[1].lastActiveMs);
      const toRemove = sorted.slice(0, sessions.size - MAX_SESSIONS);
      for (const [key] of toRemove) sessions.delete(key);
    }
    // Hard cap on turns (orphaned safety net)
    if (turns.size > MAX_TURNS) {
      const sorted = [...turns.entries()].sort((a, b) => a[1].startedAt - b[1].startedAt);
      const toRemove = sorted.slice(0, turns.size - MAX_TURNS);
      for (const [key] of toRemove) turns.delete(key);
    }
    // Evict stale lineage data (same TTL as sessions)
    lineageTracker.evict(SESSION_TTL_MS);
  }

  // Run eviction periodically (unref'd so it won't keep the process alive)
  const evictionTimer = safeSetTimeout(function tick() {
    evictStale();
    safeSetTimeout(tick, 5 * 60 * 1000); // every 5 minutes
  }, 5 * 60 * 1000);

  /** Track a flush promise and auto-remove when done */
  function trackFlush(promise) {
    pendingFlushes.add(promise);
    promise.finally(() => pendingFlushes.delete(promise));
  }

  /** Await all in-flight flushes (used for graceful shutdown) */
  async function flushAll() {
    if (pendingFlushes.size > 0) {
      await Promise.allSettled([...pendingFlushes]);
    }
  }

  // ── Retry queue: events that failed after all retries get a second chance ──
  /** @type {Array<object>} events waiting for retry */
  let retryQueue = [];

  /** Enqueue failed events for deferred retry (bounded to prevent memory leak) */
  function enqueueForRetry(events) {
    if (events.length === 0) return;
    const spaceLeft = MAX_RETRY_QUEUE - retryQueue.length;
    if (spaceLeft <= 0) {
      api.logger.warn(
        `[langfuse-tracer] Retry queue full (${MAX_RETRY_QUEUE}), dropping ${events.length} events`
      );
      return;
    }
    const toAdd = events.slice(0, spaceLeft);
    retryQueue.push(...toAdd);
    if (toAdd.length < events.length) {
      api.logger.warn(
        `[langfuse-tracer] Retry queue nearly full, dropped ${events.length - toAdd.length} events`
      );
    }
    api.logger.info(`[langfuse-tracer] Queued ${toAdd.length} events for retry (total: ${retryQueue.length})`);
  }

  /** Periodically drain the retry queue */
  async function drainRetryQueue() {
    if (retryQueue.length === 0) return;
    // Swap out the queue atomically — new failures during send go into the fresh array
    const events = retryQueue;
    retryQueue = [];
    api.logger.info(`[langfuse-tracer] Retrying ${events.length} queued events…`);
    let stillFailed;
    try {
      stillFailed = await postBatch(baseUrl, authHeader, events, api.logger);
    } catch (err) {
      // postBatch itself threw — put everything back so nothing is lost
      api.logger.warn(`[langfuse-tracer] drainRetryQueue postBatch threw: ${String(err)}`);
      stillFailed = events;
    }
    if (stillFailed.length > 0) {
      enqueueForRetry(stillFailed);
    }
  }

  // Run retry queue drain periodically (unref'd)
  safeSetTimeout(function retryTick() {
    const p = drainRetryQueue().catch((err) => {
      api.logger.warn(`[langfuse-tracer] Retry queue drain error: ${String(err)}`);
    });
    trackFlush(p);
    safeSetTimeout(retryTick, RETRY_QUEUE_INTERVAL);
  }, RETRY_QUEUE_INTERVAL);

  // Graceful shutdown: flush pending data + drain retry queue before process exits
  const onBeforeExit = async () => {
    if (pendingFlushes.size > 0 || retryQueue.length > 0) {
      api.logger.info(
        `[langfuse-tracer] Shutdown: flushing ${pendingFlushes.size} upload(s) + ${retryQueue.length} queued events…`
      );
      await flushAll();
      await drainRetryQueue();
      await flushAll(); // wait for retry drain flush too
    }
  };
  process.on("beforeExit", onBeforeExit);

  // Also flush on SIGINT/SIGTERM — beforeExit does NOT fire on explicit process.exit() or signals
  const onSignalExit = () => {
    if (pendingFlushes.size > 0 || retryQueue.length > 0) {
      api.logger.info(
        `[langfuse-tracer] Signal shutdown: flushing ${pendingFlushes.size} upload(s) + ${retryQueue.length} queued events…`
      );
      // Use sync-ish best-effort: schedule the flush and give it a moment
      Promise.resolve()
        .then(() => flushAll())
        .then(() => drainRetryQueue())
        .then(() => flushAll())
        .catch(() => {})
        .finally(() => process.exit(0));
    }
  };
  process.on("SIGINT", onSignalExit);
  process.on("SIGTERM", onSignalExit);

  function sessionKey(ctx) {
    return ctx.sessionKey ?? "default";
  }

  function turnKey(ctx) {
    // Each agent turn is uniquely keyed by agentId (sub-agents have different agentIds)
    return ctx.agentId ?? ctx.sessionKey ?? "default";
  }

  function getOrCreateSession(ctx) {
    const key = sessionKey(ctx);
    if (!sessions.has(key)) {
      sessions.set(key, new SessionState(key));
    }
    const session = sessions.get(key);
    session.touch();
    return session;
  }

  function getTurn(ctx) {
    return turns.get(turnKey(ctx));
  }

  // ────────────────────────────────────────────────────────────────────────
  // 1. before_agent_start — create session + agent turn
  // ────────────────────────────────────────────────────────────────────────
  api.on("before_agent_start", (event, ctx) => {
    try {
    const session = getOrCreateSession(ctx);
    const key = turnKey(ctx);

    // Detect sub-agent: if there's already an active agent in this session,
    // the new agent is a child of the topmost active agent.
    const stack = session.activeAgentStack;
    const parentTurnKey = stack.length > 0 ? stack[stack.length - 1] : null;
    const parentTurn = parentTurnKey ? turns.get(parentTurnKey) : null;
    const parentAgentSpanId = parentTurn ? parentTurn.agentSpanId : null;

    // Push this agent onto the nesting stack
    stack.push(key);

    // Create turn state with shared traceId and parent link
    const turn = new TurnState(session.traceId, parentAgentSpanId);
    turn.prompt = event.prompt ?? "";
    turn.agentId = ctx.agentId ?? null;

    // ── Tracking: assign IDs ──
    turn.trackingAgentId = getOrCreateAgentId(ctx.agentId || "default");
    turn.trackingSessionId = session.trackingSessionId;
    if (parentTurn) {
      turn.parentTrackingAgentId = parentTurn.trackingAgentId;
      // Last action of parent becomes the parent_action for delegation
      const parentRecords = parentTurn.actionRecords;
      if (parentRecords.length > 0) {
        turn.parentTrackingActionId = parentRecords[parentRecords.length - 1].action_id;
      }
    }

    // ── Tracking: register user prompt as untrusted data ──
    if (turn.prompt) {
      const promptDataId = lineageTracker.registerData({
        source: "user_input",
        taintLevel: trackingConfig.taint.userInputTaint,
        taintSource: "user_input",
        actionId: null,
        agentId: turn.trackingAgentId,
      });
      turn.promptDataId = promptDataId;
      turn.activeDataIds.push(promptDataId);
    }

    turns.set(key, turn);
    } catch (err) {
      api.logger.warn(`[langfuse-tracer] before_agent_start error: ${String(err)}`);
    }
  });

  // ────────────────────────────────────────────────────────────────────────
  // 2. llm_input — LLM request payload
  // ────────────────────────────────────────────────────────────────────────
  api.on("llm_input", (event, ctx) => {
    try {
    const turn = getTurn(ctx);
    if (!turn) return;
    turn.llm = turn.llm || {};
    turn.llm.generationId = randomId();
    turn.llm.startTime = nowISO();
    turn.llm.startMs = Date.now();
    turn.llm.provider = event.provider;
    turn.llm.model = event.model;
    turn.llm.runId = event.runId;
    turn.llm.sessionId = event.sessionId;
    turn.llm.input = {
      systemPrompt: event.systemPrompt ?? "",
      prompt: event.prompt ?? "",
      historyMessageCount: Array.isArray(event.historyMessages)
        ? event.historyMessages.length
        : 0,
      imagesCount: event.imagesCount ?? 0,
    };
    // ── Tracking: generate LLM action_id ──
    turn.llmActionId = genActionId();
    } catch (err) {
      api.logger.warn(`[langfuse-tracer] llm_input error: ${String(err)}`);
    }
  });

  // ────────────────────────────────────────────────────────────────────────
  // 3. llm_output — LLM response payload
  // ────────────────────────────────────────────────────────────────────────
  api.on("llm_output", (event, ctx) => {
    try {
    const turn = getTurn(ctx);
    if (!turn) return;
    if (!turn.llm) {
      turn.llm = { generationId: randomId(), startTime: nowISO(), startMs: Date.now() };
    }
    turn.llm.completionStartTime = turn.llm.completionStartTime ?? nowISO();
    turn.llm.endTime = nowISO();
    turn.llm.provider = turn.llm.provider ?? event.provider;
    turn.llm.model = turn.llm.model ?? event.model;

    // Extract LLM response text — try multiple field names for compatibility
    const responseText =
      (Array.isArray(event.assistantTexts) && event.assistantTexts.length > 0
        ? event.assistantTexts.join("\n")
        : null) ??
      event.text ??
      event.response ??
      event.content ??
      event.lastAssistant ??
      (typeof event.output === "string" ? event.output : null) ??
      (event.message?.content) ??
      (Array.isArray(event.choices)
        ? event.choices.map((c) => c.message?.content ?? c.text ?? "").join("\n")
        : null) ??
      "";
    turn.llm.output = responseText;
    turn.llm.lastAssistant = event.lastAssistant;

    // Debug: log event keys so we can identify the correct field
    api.logger.info(
      `[langfuse-tracer] llm_output event keys: [${Object.keys(event).join(", ")}], ` +
      `output length: ${responseText.length}`
    );

    if (event.usage) {
      const u = event.usage;
      turn.llm.usageDetails = {
        input_tokens: u.input ?? 0,
        output_tokens: u.output ?? 0,
        total_tokens: u.total ?? (u.input ?? 0) + (u.output ?? 0),
      };
      if (u.cacheRead != null || u.cacheWrite != null) {
        turn.llm.usageDetails.input_tokens_details = {
          cached_tokens: u.cacheRead ?? 0,
        };
        turn.llm.usageDetails.output_tokens_details = {
          cache_creation_tokens: u.cacheWrite ?? 0,
        };
      }
      turn.llm.usage = {
        input: u.input ?? 0,
        output: u.output ?? 0,
        total: u.total ?? (u.input ?? 0) + (u.output ?? 0),
        unit: "TOKENS",
      };
    }

    // ── Tracking: register LLM output as data, propagate taint, build action record ──
    const llmOutputDataId = lineageTracker.registerData({
      source: "llm_output",
      taintLevel: "trusted", // LLM output starts trusted, taint propagation may change
      taintSource: "llm_inference",
      actionId: turn.llmActionId,
      agentId: turn.trackingAgentId,
    });
    turn.llmOutputDataIds.push(llmOutputDataId);
    turn.activeDataIds.push(llmOutputDataId);

    // Data inputs = prompt data + any prior active data
    const llmInputDataIds = turn.promptDataId ? [turn.promptDataId] : [];

    // Record the transform in lineage DAG
    lineageTracker.recordTransform(turn.llmActionId, llmInputDataIds, [llmOutputDataId]);

    // Build a temporary action record for taint propagation
    const llmActionRecord = ActionRecordBuilder.buildFromLLMInference({
      agentId: turn.trackingAgentId,
      sessionId: turn.trackingSessionId,
      turnId: turn.trackingTurnId,
      actionId: turn.llmActionId,
      parentActionId: turn.parentTrackingActionId,
      parentAgentId: turn.parentTrackingAgentId,
      model: turn.llm.model,
      provider: turn.llm.provider,
      input: turn.llm.input,
      output: responseText ? responseText.slice(0, 500) : undefined,
      durationMs: turn.llm.startMs ? Date.now() - turn.llm.startMs : undefined,
      dataInputs: llmInputDataIds,
      dataOutputs: [llmOutputDataId],
    });

    // Propagate taint through LLM inference
    const llmTaint = taintEngine.propagateTaint(llmActionRecord);
    llmActionRecord.taint = {
      inherited_from: llmTaint.inheritedFrom,
      taint_level: llmTaint.outputTaintLevel,
      taint_source: llmTaint.taintSource,
    };

    // Score risk
    const llmRisk = riskScorer.scoreAction(turn.trackingSessionId, llmActionRecord);
    llmActionRecord.risk = {
      cumulative_score: llmRisk.cumulativeScore,
      delta: llmRisk.delta,
      flags: llmRisk.flags,
    };

    turn.actionRecords.push(llmActionRecord);

    } catch (err) {
      api.logger.warn(`[langfuse-tracer] llm_output error: ${String(err)}`);
    }
  });

  // ────────────────────────────────────────────────────────────────────────
  // 4. before_tool_call — tool invocation input
  // ────────────────────────────────────────────────────────────────────────
  api.on("before_tool_call", (event, ctx) => {
    try {
    const turn = getTurn(ctx);
    if (!turn) return;
    const spanId = randomId();
    const toolCallId = event.toolCallId ?? ctx.toolCallId ?? spanId;
    const trackingActionId = genActionId();
    turn.toolSpans.set(toolCallId, {
      spanId,
      toolName: event.toolName,
      input: safeStringify(event.params),
      startTime: nowISO(),
      startMs: Date.now(),
      runId: event.runId ?? ctx.runId,
      // ── Tracking fields ──
      trackingActionId,
      dataInputs: [...turn.activeDataIds], // snapshot of active data entering this tool
    });

    // ── Active mode: pre-flight Beam check ──
    if (trackingConfig.mode === "active") {
      // Build a preliminary action record to check risk before execution
      const preflightRecord = ActionRecordBuilder.buildFromToolCall({
        agentId: turn.trackingAgentId,
        sessionId: turn.trackingSessionId,
        turnId: turn.trackingTurnId,
        actionId: trackingActionId,
        parentActionId: turn.parentTrackingActionId,
        parentAgentId: turn.parentTrackingAgentId,
        toolName: event.toolName,
        input: event.params,
        dataInputs: [...turn.activeDataIds],
        dataOutputs: [],
      });
      const preflightTaint = taintEngine.propagateTaint(preflightRecord);
      preflightRecord.taint = {
        inherited_from: preflightTaint.inheritedFrom,
        taint_level: preflightTaint.outputTaintLevel,
        taint_source: preflightTaint.taintSource,
      };
      const { isSink, alert: sinkAlert } = taintEngine.checkSink(preflightRecord);
      const currentScore = riskScorer.getScore(turn.trackingSessionId);
      const { shouldIntervene, intervention } = beamIntervenor.evaluate({
        sessionId: turn.trackingSessionId,
        actionRecord: preflightRecord,
        cumulativeScore: currentScore,
        sinkAlert,
      });
      if (shouldIntervene && intervention) {
        const span = turn.toolSpans.get(toolCallId);
        span.beamIntervention = intervention;
        api.logger.warn(
          `[langfuse-tracer] BEAM INTERVENTION (${intervention.type}): ${intervention.reason} ` +
          `on tool ${event.toolName}, score=${currentScore.toFixed(3)}`
        );
        // In active+block mode, signal to the framework to block
        if (intervention.type === "block" && typeof ctx.block === "function") {
          ctx.block(beamIntervenor.buildContextMessage(intervention));
        }
      }
    }
    } catch (err) {
      api.logger.warn(`[langfuse-tracer] before_tool_call error: ${String(err)}`);
    }
  });

  // ────────────────────────────────────────────────────────────────────────
  // 5. after_tool_call — tool invocation output
  // ────────────────────────────────────────────────────────────────────────
  api.on("after_tool_call", (event, ctx) => {
    try {
    const turn = getTurn(ctx);
    if (!turn) return;
    const toolCallId = event.toolCallId ?? ctx.toolCallId ?? "";
    const span = turn.toolSpans.get(toolCallId);
    if (span) {
      span.endTime = nowISO();
      span.durationMs =
        event.durationMs ?? (span.startMs ? Date.now() - span.startMs : undefined);
      span.output = safeStringify(event.result);
      span.error = event.error ?? undefined;
      span.level = event.error ? "ERROR" : "DEFAULT";

      // ── Tracking: register tool output as data, taint propagation, risk scoring ──
      const outputDataId = lineageTracker.registerData({
        source: `tool_output:${span.toolName}`,
        taintLevel: trackingConfig.taint.defaultExternalTaint,
        taintSource: `tool:${span.toolName}`,
        actionId: span.trackingActionId,
        agentId: turn.trackingAgentId,
      });
      span.dataOutputs = [outputDataId];
      turn.activeDataIds.push(outputDataId);

      // Record transform in lineage DAG
      const inputDataIds = span.dataInputs || [];
      lineageTracker.recordTransform(span.trackingActionId, inputDataIds, [outputDataId]);

      // Build full action record
      const toolActionRecord = ActionRecordBuilder.buildFromToolCall({
        agentId: turn.trackingAgentId,
        sessionId: turn.trackingSessionId,
        turnId: turn.trackingTurnId,
        actionId: span.trackingActionId,
        parentActionId: turn.parentTrackingActionId,
        parentAgentId: turn.parentTrackingAgentId,
        toolName: span.toolName,
        input: event.params ?? span.input,
        output: event.result,
        durationMs: span.durationMs,
        dataInputs: inputDataIds,
        dataOutputs: [outputDataId],
      });

      // Taint propagation
      const toolTaint = taintEngine.propagateTaint(toolActionRecord);
      toolActionRecord.taint = {
        inherited_from: toolTaint.inheritedFrom,
        taint_level: toolTaint.outputTaintLevel,
        taint_source: toolTaint.taintSource,
      };

      // Sink detection
      const { alert: sinkAlert } = taintEngine.checkSink(toolActionRecord);

      // Risk scoring
      const toolRisk = riskScorer.scoreAction(turn.trackingSessionId, toolActionRecord);
      toolActionRecord.risk = {
        cumulative_score: toolRisk.cumulativeScore,
        delta: toolRisk.delta,
        flags: toolRisk.flags,
      };

      // Store the tracking metadata on the span for later embedding
      span.trackingMeta = ActionRecordBuilder.toTrackingMetadata(toolActionRecord);
      turn.actionRecords.push(toolActionRecord);

      // Passive mode Beam evaluation (log alerts)
      if (trackingConfig.mode === "passive") {
        const { shouldIntervene, intervention } = beamIntervenor.evaluate({
          sessionId: turn.trackingSessionId,
          actionRecord: toolActionRecord,
          cumulativeScore: toolRisk.cumulativeScore,
          sinkAlert,
        });
        if (shouldIntervene && intervention) {
          span.beamIntervention = intervention;
          api.logger.warn(
            `[langfuse-tracer] BEAM ALERT (passive): ${intervention.reason} ` +
            `on tool ${span.toolName}, score=${toolRisk.cumulativeScore.toFixed(3)}`
          );
        }
      }
    } else {
      // Late-arriving tool result without a matching before_tool_call
      const spanId = randomId();
      const trackingActionId = genActionId();
      turn.toolSpans.set(toolCallId || spanId, {
        spanId,
        toolName: event.toolName,
        input: safeStringify(event.params),
        startTime: nowISO(),
        endTime: nowISO(),
        durationMs: event.durationMs,
        output: safeStringify(event.result),
        error: event.error ?? undefined,
        level: event.error ? "ERROR" : "DEFAULT",
        runId: event.runId ?? ctx.runId,
        trackingActionId,
        dataInputs: [...turn.activeDataIds],
        dataOutputs: [],
      });
    }
    } catch (err) {
      api.logger.warn(`[langfuse-tracer] after_tool_call error: ${String(err)}`);
    }
  });

  // ────────────────────────────────────────────────────────────────────────
  // 6. agent_end — flush to Langfuse
  // ────────────────────────────────────────────────────────────────────────
  api.on("agent_end", (event, ctx) => {
    try {
    const key = turnKey(ctx);
    const turn = turns.get(key);
    turns.delete(key);
    if (!turn) return;

    // Debug: log event keys + llm output status
    api.logger.info(
      `[langfuse-tracer] agent_end event keys: [${Object.keys(event).join(", ")}], ` +
      `llm captured: ${!!turn.llm}, llm output length: ${turn.llm?.output?.length ?? 0}`
    );

    const session = getOrCreateSession(ctx);

    // Pop this agent from the nesting stack
    const stack = session.activeAgentStack;
    const idx = stack.lastIndexOf(key);
    if (idx !== -1) stack.splice(idx, 1);

    const { agentId, sessionKey: sessKey } = ctx;
    const { success, error, durationMs, messages } = event;
    const endTime = nowISO();
    const startTime = new Date(turn.startedAt).toISOString();
    const traceId = turn.traceId;
    const agentSpanId = turn.agentSpanId;

    // Fallback: if llm_output didn't capture a response, try to extract from
    // agent_end's messages array (last assistant message).
    if (turn.llm && !turn.llm.output && Array.isArray(messages)) {
      for (let i = messages.length - 1; i >= 0; i--) {
        const m = messages[i];
        if (m && (m.role === "assistant" || m.type === "assistant")) {
          turn.llm.output = m.content ?? m.text ?? safeStringify(m) ?? "";
          break;
        }
      }
    }
    // Also try event.response / event.output as last resort
    if (turn.llm && !turn.llm.output) {
      turn.llm.output = event.response ?? event.output ?? event.text ?? "";
    }

    const batch = [];

    // ── trace-create (once per session) ─────────────────────────────────
    // First agent_end in this session creates the trace; subsequent ones
    // update it via trace-create with the same body.id (Langfuse upserts).
    if (!session.traceCreated) {
      session.traceCreated = true;
      batch.push({
        id: randomId(),
        type: "trace-create",
        timestamp: endTime,
        body: {
          id: traceId,
          timestamp: startTime,
          name: "openclaw-session",
          sessionId: sessKey ?? undefined,
          userId: agentId ?? "unknown",
          release,
          version: PLUGIN_VERSION,
          environment,
          tags: compact(["openclaw", agentId, ctx.channelId]),
          input: turn.prompt || undefined,
          output: turn.llm?.output || undefined,
          metadata: {
            trigger: ctx.trigger,
          },
        },
      });
    } else {
      // Update trace output/metadata with latest turn info
      batch.push({
        id: randomId(),
        type: "trace-create",
        timestamp: endTime,
        body: {
          id: traceId,
          output: turn.llm?.output || undefined,
          metadata: {
            lastAgentId: agentId,
            trigger: ctx.trigger,
          },
        },
      });
    }

    // ── Compute turn-level tracking summary ──
    const turnTrackingSummary = {
      agent_id: turn.trackingAgentId,
      session_id: turn.trackingSessionId,
      turn_id: turn.trackingTurnId,
      parent_agent_id: turn.parentTrackingAgentId,
      parent_action_id: turn.parentTrackingActionId,
      cumulative_risk: riskScorer.getScore(turn.trackingSessionId),
      action_count: turn.actionRecords.length,
      taint_alerts: taintEngine.getAlerts().filter(
        (a) => turn.actionRecords.some((r) => r.action_id === a.actionId)
      ),
      beam_interventions: beamIntervenor.getInterventionHistory(turn.trackingSessionId),
    };

    // ── span-create[agent] — the agent turn itself ──────────────────────
    // This is the key hierarchy node: an agent-type span.
    // Root agents → parentObservationId is undefined (direct child of trace)
    // Sub-agents → parentObservationId is parent agent's agentSpanId
    batch.push({
      id: randomId(),
      type: "span-create",
      timestamp: endTime,
      body: {
        id: agentSpanId,
        traceId,
        parentObservationId: turn.parentAgentSpanId ?? undefined,
        name: `agent:${agentId ?? "unknown"}`,
        startTime,
        endTime,
        input: turn.prompt || undefined,
        output: turn.llm?.output || undefined,
        level: success ? "DEFAULT" : "ERROR",
        statusMessage: error ?? undefined,
        version: PLUGIN_VERSION,
        environment,
        metadata: {
          observationType: "agent",
          agentId,
          success,
          error: error ?? undefined,
          durationMs,
          messageCount: Array.isArray(messages) ? messages.length : 0,
          toolCallCount: turn.toolSpans.size,
          provider: turn.llm?.provider,
          model: turn.llm?.model,
          isSubAgent: turn.parentAgentSpanId != null,
          // ── Tracking metadata ──
          tracking: turnTrackingSummary,
        },
      },
    });

    // ── generation-create — LLM call (child of agent span) ──────────────
    if (turn.llm) {
      const gen = turn.llm;
      batch.push({
        id: randomId(),
        type: "generation-create",
        timestamp: endTime,
        body: {
          id: gen.generationId,
          traceId,
          parentObservationId: agentSpanId,
          name: "llm",
          startTime: gen.startTime ?? startTime,
          endTime: gen.endTime ?? endTime,
          completionStartTime: gen.completionStartTime ?? undefined,
          model: gen.model ?? undefined,
          modelParameters: gen.provider
            ? { provider: gen.provider }
            : undefined,
          input: gen.input ?? undefined,
          output: gen.output ?? undefined,
          usageDetails: gen.usageDetails ?? undefined,
          usage: gen.usage ?? undefined,
          level: success ? "DEFAULT" : "ERROR",
          statusMessage: error ?? undefined,
          version: PLUGIN_VERSION,
          environment,
          metadata: {
            runId: gen.runId,
            sessionId: gen.sessionId,
            // ── Tracking metadata ──
            tracking: turn.actionRecords.find(
              (r) => r.action_type === "llm_inference"
            )
              ? ActionRecordBuilder.toTrackingMetadata(
                  turn.actionRecords.find((r) => r.action_type === "llm_inference")
                ).tracking
              : undefined,
          },
        },
      });
    }

    // ── span-create[tool] × N — tool calls (children of agent span) ────
    for (const [toolCallId, span] of turn.toolSpans) {
      batch.push({
        id: randomId(),
        type: "span-create",
        timestamp: endTime,
        body: {
          id: span.spanId,
          traceId,
          parentObservationId: agentSpanId,
          name: span.toolName ?? "unknown",
          startTime: span.startTime ?? startTime,
          endTime: span.endTime ?? endTime,
          input: span.input ?? undefined,
          output: span.output ?? undefined,
          level: span.level ?? "DEFAULT",
          statusMessage: span.error ?? undefined,
          version: PLUGIN_VERSION,
          environment,
          metadata: {
            observationType: "tool",
            toolCallId,
            toolName: span.toolName,
            durationMs: span.durationMs,
            runId: span.runId,
            // ── Tracking metadata ──
            ...(span.trackingMeta || {}),
            ...(span.beamIntervention ? { beamIntervention: span.beamIntervention } : {}),
          },
        },
      });
    }

    // ── score-create (turn success/failure) ─────────────────────────────
    batch.push({
      id: randomId(),
      type: "score-create",
      timestamp: endTime,
      body: {
        id: randomId(),
        traceId,
        name: "turn_success",
        value: success ? 1 : 0,
        dataType: "BOOLEAN",
        comment: error ?? undefined,
      },
    });

    // ── score-create (cumulative risk score) ─────────────────────────────
    const riskScore = riskScorer.getScore(turn.trackingSessionId);
    batch.push({
      id: randomId(),
      type: "score-create",
      timestamp: endTime,
      body: {
        id: randomId(),
        traceId,
        observationId: agentSpanId,
        name: "cumulative_risk",
        value: Math.round(riskScore * 1000) / 1000,
        dataType: "NUMERIC",
        comment: turnTrackingSummary.taint_alerts.length > 0
          ? `Taint alerts: ${turnTrackingSummary.taint_alerts.length}`
          : undefined,
      },
    });

    // Fire-and-forget: don't block the agent while uploading
    const flushPromise = postBatch(baseUrl, authHeader, batch, api.logger)
      .then((failedEvents) => {
        if (failedEvents && failedEvents.length > 0) {
          enqueueForRetry(failedEvents);
        }
      })
      .catch((err) => {
        api.logger.warn(`[langfuse-tracer] Background flush error: ${String(err)}`);
        // On unexpected error, try to save all events for retry
        enqueueForRetry(batch);
      });
    trackFlush(flushPromise);
    } catch (err) {
      api.logger.warn(`[langfuse-tracer] agent_end error: ${String(err)}`);
    }
  });
}
