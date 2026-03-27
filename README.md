<p align="center">
  <h1 align="center">openclaw-tracer</h1>
  <p align="center">
    <strong>Agentic AI Security Observability for OpenClaw</strong>
  </p>
  <p align="center">
    Full-stack agent tracing with taint analysis, data lineage, and real-time risk intervention
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#how-it-works">How It Works</a> &middot;
    <a href="#configuration">Configuration</a> &middot;
    <a href="#api-reference">API Reference</a>
  </p>
</p>

---

## Why openclaw-tracer?

LLM agents can read databases, send emails, execute code, and delegate to sub-agents. **What happens when untrusted user input flows through three tool calls and ends up in an outbound email?**

openclaw-tracer answers that question. It is an [OpenClaw](https://github.com/openclaw/openclaw) plugin that provides:

- **Observability** — hierarchical traces of every agent turn, LLM call, and tool invocation, sent to [Langfuse](https://langfuse.com)
- **Security** — real-time taint propagation, data lineage tracking, and cumulative risk scoring that catches dangerous data flows before they cause harm

Zero dependencies. Drop-in installation. No image rebuild.

### Key capabilities

| | Capability | Description |
|---|---|---|
| **ID** | Five-level ID hierarchy | `org` > `agent` > `session` > `turn` > `action` + `data` — trace any event at any granularity |
| **DAG** | Data lineage graph | Every data unit gets a `data_id` that follows it across agents, sessions, and tool boundaries |
| **TAINT** | Taint propagation | Untrusted inputs (user prompts, external APIs) propagate contamination through the processing pipeline |
| **SINK** | Sink detection | Alerts when tainted data reaches sensitive operations — `send_email`, `exec`, `http_post`, etc. |
| **RISK** | Cumulative risk scoring | Five-dimensional scoring across taint, privilege, sensitivity, boundary crossings, and behavioral drift |
| **BEAM** | Beam intervention | Passive mode logs alerts; active mode blocks dangerous tool calls before execution |
| **CHAIN** | Cross-agent correlation | `parent_action_id` + `parent_agent_id` stitch execution and data chains across delegated sub-agents |

---

## How it works

### Dual-chain architecture

openclaw-tracer runs two interleaved chains simultaneously:

```
 Execution Chain                    Data Lineage Chain
 "who did what, when"               "where data came from, where it went"
       │                                   │
       │          cross-reference          │
       └──────────────┬───────────────────┘
                      │
               Every action carries
             execution ID + data lineage ID
```

**Execution chain** — reconstructs agent behavior:

```
ses_20260327T102300_7k2m
│
├── trn_001
│   ├── act_001 [llm_inference]  "understand user prompt"
│   ├── act_002 [tool_call]      "read_crm_contact"
│   └── act_003 [tool_call]      "query_order_history"
│
├── trn_002
│   ├── act_004 [llm_inference]  "synthesize analysis"
│   └── act_005 [tool_call]      "send_email"  ← SINK DETECTED
│
└── trn_003
    └── act_006 [llm_inference]  "generate summary"
```

**Data lineage chain** — tracks data flow and contamination:

```
dat_001 (user_input — untrusted)
  │
  ├──→ act_002 ──→ dat_002 (CRM + user input = mixed)
  ├──→ act_003 ──→ dat_003 (order history = trusted)
  │
  └──→ act_004 consumes dat_002 + dat_003 ──→ dat_004 (analysis = mixed)
        │
        └──→ act_005 consumes dat_004 ──→ send_email(dat_004)
             ⚠ ALERT: mixed data reaching external sink!
```

### Taint propagation rules

| Input taint | Output taint | Rule |
|:---|:---|:---|
| All `trusted` | `trusted` | Clean pipeline |
| Any `untrusted` + `trusted` | `mixed` | Contamination via mixing |
| All `untrusted` | `untrusted` | Fully untrusted path |
| Any `mixed` | `mixed` | Mixed stays mixed |

### Risk scoring (five dimensions)

| Dimension | Weight | Measures |
|:---|:---:|:---|
| Taint severity | 0.30 | Contamination level of data flowing through the action |
| Privilege escalation | 0.25 | Tool call exceeding agent's authorized scope |
| Data sensitivity | 0.20 | PII, credentials, financial, or health data accessed |
| Boundary crossing | 0.15 | Jump from internal read to external write |
| Behavioral drift | 0.10 | Tool usage deviating from agent's historical baseline |

The cumulative score increases monotonically per session. When it crosses the Beam threshold (default `0.7`), intervention triggers.

### Beam intervention modes

| Mode | Behavior |
|:---|:---|
| **`passive`** (default) | Logs warnings to Langfuse metadata — observe without blocking |
| **`active`** | Pre-flight check before tool execution; can `block`, `context_inject`, or `warn` |

Triggers: cumulative risk threshold, tainted data at sink, high single-step delta, or privilege escalation.

---

## Quick Start

### 1. Install

```bash
mkdir -p /path/to/openclaw/workspace/.openclaw/extensions
cp -r openclaw-tracer/ /path/to/openclaw/workspace/.openclaw/extensions/
```

### 2. Configure environment

```yaml
environment:
  # Required
  LANGFUSE_PUBLIC_KEY: pk-lf-xxxxxxxxxxxxxxxxxxxx
  LANGFUSE_SECRET_KEY: sk-lf-xxxxxxxxxxxxxxxxxxxx
  LANGFUSE_BASE_URL: http://172.21.0.1:3050
  # Optional
  LANGFUSE_RELEASE: "v1.2.3"
  LANGFUSE_ENVIRONMENT: "production"
```

| Deployment | LANGFUSE_BASE_URL |
|:---|:---|
| Same Docker host | `http://172.21.0.1:3050` |
| Same Compose stack | `http://langfuse-web:3000` |
| Different LAN host | `http://<langfuse-host-ip>:3050` |
| Langfuse Cloud | `https://cloud.langfuse.com` |

### 3. Verify

Restart the gateway and check logs:

```
[openclaw-tracer] Langfuse tracing enabled → http://172.21.0.1:3050
[openclaw-tracer] Tracking subsystem initialized (mode: passive, beam threshold: 0.7)
```

---

## What you see in Langfuse

### Trace tree

```
Trace (openclaw-session)
│   score: turn_success = 0 | 1
│   score: cumulative_risk = 0.0 ~ 1.0
│
└─ Span[agent] (agent:<agentId>)
     │  metadata.tracking = { agent_id, session_id, turn_id, cumulative_risk, taint_alerts, ... }
     │
     ├─ Generation (llm)
     │     metadata.tracking = { action_id, data_inputs, data_outputs, taint, risk }
     │
     ├─ Span[tool] (read_crm_contact)
     │     metadata.tracking = { action_id, data_inputs, data_outputs, taint, risk }
     │
     ├─ Span[tool] (send_email)
     │     metadata.tracking = { ... taint.taint_level: "mixed", risk.flags: ["tainted_data_at_sink"] }
     │     metadata.beamIntervention = { type: "warn", reason: "tainted_data_at_sink" }
     │
     └─ Span[agent] (agent:<subAgentId>)                 ← nested sub-agent
          metadata.tracking = { parent_agent_id, parent_action_id, ... }
```

### Tracking metadata structure

```json
{
  "tracking": {
    "agent_id": "agt_20260327_a3f8c1",
    "session_id": "ses_20260327T102300_7k2m",
    "turn_id": "trn_20260327T102301_p9x4",
    "action_id": "act_20260327T102301_q1w2",
    "parent_action_id": null,
    "parent_agent_id": null,
    "action_type": "tool_call",
    "data_inputs": ["dat_..._m5n6"],
    "data_outputs": ["dat_..._r7s8"],
    "taint": {
      "taint_level": "mixed",
      "inherited_from": ["dat_..._m5n6"],
      "taint_source": "user_input+tool:read_crm"
    },
    "risk": {
      "cumulative_score": 0.72,
      "delta": 0.12,
      "flags": ["tainted_data_at_sink", "pii_mixed_external"]
    }
  }
}
```

---

## Configuration

All tracking configuration is optional. Defaults provide a sensible passive-observability baseline.

```js
{
  mode: "passive",              // "passive" | "active"
  orgId: "org_default",         // tenant identifier

  risk: {
    beamThreshold: 0.7,         // trigger Beam intervention
    deltaAlertThreshold: 0.3,   // single-step alert threshold
    maxScore: 1.0,              // cumulative score cap
  },

  weights: {                    // must sum to 1.0
    taintSeverity: 0.30,
    privilegeEscalation: 0.25,
    dataSensitivity: 0.20,
    boundaryCrossing: 0.15,
    behavioralDrift: 0.10,
  },

  taint: {
    defaultExternalTaint: "untrusted",
    defaultInternalTaint: "trusted",
    userInputTaint: "untrusted",
  },

  defaultAgentPosture: {
    allowedTools: [],             // empty = allow all
    dataAccessLevel: "standard",  // standard | restricted | elevated
    maxRiskTolerance: 0.8,
  },
}
```

---

## API Reference

### Hooks

| Hook | When | What openclaw-tracer does |
|:---|:---|:---|
| `before_agent_start` | Agent turn begins | Assign `session_id`, `turn_id`, `agent_id`; register user prompt as untrusted `data_id` |
| `llm_input` | Before LLM call | Capture model/provider; generate LLM `action_id` |
| `llm_output` | After LLM response | Register output `data_id`; taint propagation; risk scoring; build LLM action record |
| `before_tool_call` | Before tool runs | Generate `action_id`; snapshot input `data_ids`; **active mode: pre-flight Beam check** |
| `after_tool_call` | After tool returns | Register output `data_id`; taint propagation; sink detection; risk scoring; Beam evaluation |
| `agent_end` | Turn complete | Compute tracking summary; embed metadata into all Langfuse spans; flush batch |

### Langfuse events emitted

| Type | Count per turn | Contains tracking? |
|:---|:---|:---|
| `trace-create` | 1 (upserted) | No |
| `span-create` (agent) | 1 | `metadata.tracking` = turn summary |
| `generation-create` | 1 | `metadata.tracking` = LLM action record |
| `span-create` (tool) | N | `metadata.tracking` = tool action record |
| `score-create` (turn_success) | 1 | No |
| `score-create` (cumulative_risk) | 1 | No |

### ID formats

| Level | Prefix | Format | Lifecycle |
|:---|:---|:---|:---|
| 0 | `org_` | from config | permanent |
| 1 | `agt_` | `agt_YYYYMMDD_hex6` | persistent across sessions |
| 2 | `ses_` | `ses_YYYYMMDDTHHMMSS_hex6` | per session |
| 3 | `trn_` | `trn_YYYYMMDDTHHMMSS_hex6` | per LLM turn |
| 4 | `act_` | `act_YYYYMMDDTHHMMSS_hex6` | per tool call / LLM inference |
| 5 | `dat_` | `dat_YYYYMMDDTHHMMSS_hex6` | follows data across all boundaries |

---

## Reliability

| Feature | Detail |
|:---|:---|
| **No hard truncation** | Data sent in full; truncated only if single event > 3 MB |
| **Batch splitting** | Auto-splits when total payload > 3 MB |
| **Retry with backoff** | Exponential backoff + jitter; respects `Retry-After` headers |
| **Retry queue** | Failed events queued (max 5000) and retried every 60s |
| **Fire-and-forget** | Uploads never block the agent |
| **Graceful shutdown** | Flushes pending uploads + retry queue on `beforeExit` |
| **Error boundaries** | All hooks wrapped in try-catch — tracing never crashes the agent |
| **Memory protection** | Session TTL (2h), hard caps, periodic lineage eviction |

---

## Project structure

```
openclaw-tracer/
├── index.js               # Plugin entry — hooks + Langfuse integration
├── config.js              # Configuration defaults and merging
├── id-generator.js        # Five-level ID generator (agt/ses/trn/act/dat)
├── data-lineage.js        # Data lineage DAG with forward/backward traversal
├── taint-engine.js        # Taint propagation, sink detection, chain tracing
├── risk-scorer.js         # Five-dimensional cumulative risk scorer
├── action-record.js       # Action Record builder for tool calls + LLM inferences
├── beam-intervention.js   # Beam intervention engine (passive/active)
├── openclaw.plugin.json   # Plugin manifest
├── package.json           # ESM module declaration
└── README.md
```

## Requirements

- OpenClaw gateway with plugin hook support
- Node.js 22+
- Self-hosted Langfuse or Langfuse Cloud
- Zero npm dependencies

---

## Debugging

```
[openclaw-tracer] Langfuse tracing enabled → http://172.21.0.1:3050
[openclaw-tracer] Tracking subsystem initialized (mode: passive, beam threshold: 0.7)
[openclaw-tracer] BEAM ALERT (passive): tainted_data_at_sink on tool send_email, score=0.720
[openclaw-tracer] BEAM INTERVENTION (block): cumulative_risk_exceeded on tool exec_command, score=0.850
```

## License

MIT
