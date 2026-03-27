/**
 * config.js — Agent 行为追踪 ID 体系配置管理
 *
 * 管理模式切换（passive/active）、风险阈值、Sink 类型定义、
 * 污点规则和风险评分权重。
 */

// ── 默认配置 ─────────────────────────────────────────────────────────────────

export const DEFAULT_CONFIG = {
  // 运行模式: "passive" = 仅记录告警, "active" = 阻止/干预高风险操作
  mode: "passive",

  // 组织租户 ID（Level 0）
  orgId: "org_default",

  // ── 风险阈值 ──────────────────────────────────────────────────────────────
  risk: {
    // Beam 干预触发阈值（累积分超过此值时触发）
    beamThreshold: 0.7,
    // 单步风险增量告警阈值
    deltaAlertThreshold: 0.3,
    // 最大累积分（归一化上限）
    maxScore: 1.0,
  },

  // ── 五维风险评分权重 ──────────────────────────────────────────────────────
  weights: {
    taintSeverity: 0.30,       // 污点严重性
    privilegeEscalation: 0.25, // 权限升级
    dataSensitivity: 0.20,     // 数据敏感度
    boundaryCrossing: 0.15,    // 跨系统边界跳跃
    behavioralDrift: 0.10,     // 行为漂移
  },

  // ── Sink 类型定义 ─────────────────────────────────────────────────────────
  // 当被污染的数据到达这些操作类型时触发告警
  sinkTypes: [
    "send_email",
    "http_post",
    "http_put",
    "exec_command",
    "terminal_exec",
    "code_exec",
    "write_file",
    "database_write",
    "api_request",
    "webhook",
    "publish_message",
  ],

  // ── 工具名到 Sink 类型的映射 ──────────────────────────────────────────────
  // 当 tool_name 匹配这些模式时视为 Sink
  sinkToolPatterns: [
    /^(send|post|put|patch|delete|exec|run|write|publish|deploy)/i,
    /email/i,
    /webhook/i,
    /terminal/i,
    /command/i,
    /shell/i,
  ],

  // ── 污点规则 ───────────────────────────────────────────────────────────────
  taint: {
    // 默认外部数据源的污点级别
    defaultExternalTaint: "untrusted",
    // 默认内部数据源的污点级别
    defaultInternalTaint: "trusted",
    // 用户输入的污点级别
    userInputTaint: "untrusted",
  },

  // ── 数据敏感度分类 ────────────────────────────────────────────────────────
  sensitiveDataPatterns: [
    { pattern: /pii/i, level: "high", label: "pii" },
    { pattern: /password|secret|token|key|credential/i, level: "critical", label: "credential" },
    { pattern: /email|phone|address|ssn|id_number/i, level: "high", label: "pii_field" },
    { pattern: /financial|payment|card|bank/i, level: "high", label: "financial" },
    { pattern: /health|medical|diagnosis/i, level: "high", label: "health" },
  ],

  // ── Agent 姿态定义（默认） ────────────────────────────────────────────────
  // 可按 agent_id 覆盖
  defaultAgentPosture: {
    allowedTools: [],       // 空 = 允许所有
    dataAccessLevel: "standard", // standard | restricted | elevated
    maxRiskTolerance: 0.8,
  },

  // ── Beam 干预消息模板 ─────────────────────────────────────────────────────
  beamMessages: {
    taintedSink: "WARNING: Tainted data reaching sensitive operation. Sanitize before proceeding.",
    highRisk: "WARNING: Cumulative risk score exceeded threshold. Review recent actions.",
    privilegeEscalation: "WARNING: Tool call exceeds agent's authorized capability scope.",
  },
};

// ── 配置加载 ─────────────────────────────────────────────────────────────────

/**
 * 深度合并用户配置与默认配置
 */
function deepMerge(target, source) {
  const result = { ...target };
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined && value !== null) {
      if (
        typeof value === "object" &&
        !Array.isArray(value) &&
        !(value instanceof RegExp) &&
        typeof target[key] === "object" &&
        !Array.isArray(target[key])
      ) {
        result[key] = deepMerge(target[key], value);
      } else {
        result[key] = value;
      }
    }
  }
  return result;
}

/**
 * 加载并合并配置
 * @param {object} userConfig - 用户自定义配置（部分覆盖）
 * @returns {object} 完整配置
 */
export function loadConfig(userConfig = {}) {
  return deepMerge(DEFAULT_CONFIG, userConfig);
}
