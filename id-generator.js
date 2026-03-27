/**
 * id-generator.js — 五层 ID 生成器
 *
 * ID 格式: {type_prefix}_{timestamp}_{random}
 *
 * Level 0: org_id     — 组织租户（从配置读取）
 * Level 1: agent_id   — Agent 实体（持久，跨会话不变）
 * Level 2: session_id — 一次会话/任务
 * Level 3: turn_id    — 一轮 LLM 推理
 * Level 4: action_id  — 一次工具调用/外部动作
 * Level 5: data_id    — 一条数据单元的血缘标识
 */

import crypto from "node:crypto";

// ── 内部工具 ─────────────────────────────────────────────────────────────────

/**
 * 生成 6 位随机十六进制字符串
 */
function randomHex6() {
  return crypto.randomBytes(3).toString("hex");
}

/**
 * 格式化当前时间为紧凑 ISO 格式 YYYYMMDDTHHMMSS
 */
function compactTimestamp() {
  const now = new Date();
  const y = now.getUTCFullYear();
  const mo = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  const h = String(now.getUTCHours()).padStart(2, "0");
  const mi = String(now.getUTCMinutes()).padStart(2, "0");
  const s = String(now.getUTCSeconds()).padStart(2, "0");
  return `${y}${mo}${d}T${h}${mi}${s}`;
}

/**
 * 仅日期部分 YYYYMMDD（用于 agent_id 等持久 ID）
 */
function dateStamp() {
  const now = new Date();
  const y = now.getUTCFullYear();
  const mo = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  return `${y}${mo}${d}`;
}

// ── 通用 ID 生成 ─────────────────────────────────────────────────────────────

/**
 * 生成带前缀的追踪 ID
 * @param {string} prefix - ID 类型前缀 (agt, ses, trn, act, dat)
 * @param {boolean} [dateOnly=false] - 是否只使用日期（不含时间）
 * @returns {string} 格式化的 ID
 */
export function generateId(prefix, dateOnly = false) {
  const ts = dateOnly ? dateStamp() : compactTimestamp();
  return `${prefix}_${ts}_${randomHex6()}`;
}

// ── 快捷方法 ─────────────────────────────────────────────────────────────────

/** 生成 Agent ID（持久，注册时生成） — agt_YYYYMMDD_random */
export function agentId() {
  return generateId("agt", true);
}

/** 生成 Session ID — ses_YYYYMMDDTHHMMSS_random */
export function sessionId() {
  return generateId("ses");
}

/** 生成 Turn ID — trn_YYYYMMDDTHHMMSS_random */
export function turnId() {
  return generateId("trn");
}

/** 生成 Action ID — act_YYYYMMDDTHHMMSS_random */
export function actionId() {
  return generateId("act");
}

/** 生成 Data ID — dat_YYYYMMDDTHHMMSS_random */
export function dataId() {
  return generateId("dat");
}

// ── Agent ID 缓存 ────────────────────────────────────────────────────────────

/**
 * Agent ID 注册表：agentKey → agent_id
 * agent_id 一旦生成就不变（持久跨会话）
 */
const agentRegistry = new Map();

/**
 * 获取或创建持久 Agent ID
 * @param {string} agentKey - Agent 标识（如 ctx.agentId）
 * @returns {string} 持久的 agent_id
 */
export function getOrCreateAgentId(agentKey) {
  if (!agentKey) agentKey = "default";
  if (!agentRegistry.has(agentKey)) {
    agentRegistry.set(agentKey, agentId());
  }
  return agentRegistry.get(agentKey);
}
