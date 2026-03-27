/**
 * risk-scorer.js — 累积风险评分器
 *
 * 五维度风险评估：
 *   1. 污点严重性 (taint_severity)
 *   2. 权限升级 (privilege_escalation)
 *   3. 数据敏感度 (data_sensitivity)
 *   4. 跨系统边界跳跃 (boundary_crossing)
 *   5. 行为漂移 (behavioral_drift)
 *
 * 累积分沿 session 时间轴单调递增，超过阈值触发 Beam 干预。
 */

// ── RiskScorer ───────────────────────────────────────────────────────────────

export class RiskScorer {
  /**
   * @param {import('./taint-engine.js').TaintEngine} taintEngine
   * @param {object} config - 完整配置
   */
  constructor(taintEngine, config) {
    this.taintEngine = taintEngine;
    this.config = config;

    /** @type {Map<string, { score: number, history: Array }>} session_id → 累积分 */
    this.sessionScores = new Map();

    /** @type {Map<string, string[]>} agent_id → 历史 tool_name 列表（行为基线） */
    this.agentBaselines = new Map();

    /** @type {Map<string, string>} action_id → 上一个 action 的 tool_name（边界检测） */
    this.lastActionTool = new Map();
  }

  /**
   * 计算单步风险增量并累积到 session
   *
   * @param {string} sessionId
   * @param {object} actionRecord - 完整 action record
   * @param {object} [agentPosture] - Agent 姿态（allowedTools, dataAccessLevel）
   * @returns {{ cumulativeScore: number, delta: number, flags: string[] }}
   */
  scoreAction(sessionId, actionRecord, agentPosture) {
    const weights = this.config.weights;
    const flags = [];

    // ── 维度 1：污点严重性 ──
    const taintDelta = this.taintEngine.assessTaintSeverity(actionRecord);
    if (taintDelta > 0.5) flags.push("high_taint_severity");

    // ── 维度 2：权限升级 ──
    const privDelta = this._assessPrivilegeEscalation(actionRecord, agentPosture);
    if (privDelta > 0.3) flags.push("privilege_escalation");

    // ── 维度 3：数据敏感度 ──
    const dataDelta = this._assessDataSensitivity(actionRecord);
    if (dataDelta > 0.5) flags.push("sensitive_data_access");

    // ── 维度 4：跨系统边界跳跃 ──
    const boundaryDelta = this._assessBoundaryCrossing(actionRecord, sessionId);
    if (boundaryDelta > 0.3) flags.push("boundary_crossing");

    // ── 维度 5：行为漂移 ──
    const driftDelta = this._assessBehavioralDrift(actionRecord);
    if (driftDelta > 0.3) flags.push("behavioral_drift");

    // 加权求和
    const delta =
      taintDelta * weights.taintSeverity +
      privDelta * weights.privilegeEscalation +
      dataDelta * weights.dataSensitivity +
      boundaryDelta * weights.boundaryCrossing +
      driftDelta * weights.behavioralDrift;

    // 累积
    const result = this._accumulate(sessionId, delta, actionRecord, flags);

    // 检查 Sink 告警标记
    const inputIds = actionRecord.data_inputs || [];
    for (const id of inputIds) {
      const taintLevel = this.taintEngine.lineage.getTaintLevel(id);
      if (taintLevel !== "trusted") {
        const toolName = actionRecord.tool_name || "";
        const isSink = this.config.sinkToolPatterns.some((p) => p.test(toolName));
        if (isSink) {
          flags.push("tainted_data_at_sink");
        }
        if (taintLevel === "mixed") flags.push("pii_mixed_external");
      }
    }

    // 更新上一个 action 记录（用于边界检测）
    this.lastActionTool.set(sessionId, actionRecord.tool_name || "");

    // 更新 Agent 行为基线
    this._updateBaseline(actionRecord);

    return {
      cumulativeScore: result.score,
      delta: Math.round(delta * 1000) / 1000,
      flags: [...new Set(flags)],
    };
  }

  /**
   * 获取 session 当前累积分
   * @param {string} sessionId
   * @returns {number}
   */
  getScore(sessionId) {
    const entry = this.sessionScores.get(sessionId);
    return entry ? entry.score : 0;
  }

  /**
   * 获取 session 的风险历史
   * @param {string} sessionId
   * @returns {Array}
   */
  getHistory(sessionId) {
    const entry = this.sessionScores.get(sessionId);
    return entry ? entry.history : [];
  }

  /**
   * Beam 干预后降低分数
   * @param {string} sessionId
   * @param {number} reduction - 降低的分数
   */
  reduceScore(sessionId, reduction) {
    const entry = this.sessionScores.get(sessionId);
    if (entry) {
      entry.score = Math.max(0, entry.score - reduction);
    }
  }

  // ── 私有方法 ───────────────────────────────────────────────────────────────

  /**
   * 累积分数
   * @private
   */
  _accumulate(sessionId, delta, actionRecord, flags) {
    if (!this.sessionScores.has(sessionId)) {
      this.sessionScores.set(sessionId, { score: 0, history: [] });
    }
    const entry = this.sessionScores.get(sessionId);
    entry.score = Math.min(entry.score + delta, this.config.risk.maxScore);
    entry.history.push({
      actionId: actionRecord.action_id,
      delta: Math.round(delta * 1000) / 1000,
      cumulativeScore: Math.round(entry.score * 1000) / 1000,
      flags,
      timestamp: new Date().toISOString(),
    });
    return entry;
  }

  /**
   * 维度 2：权限升级评估
   * 检查工具调用是否超出 Agent 的授权范围
   * @private
   */
  _assessPrivilegeEscalation(actionRecord, agentPosture) {
    if (!agentPosture) agentPosture = this.config.defaultAgentPosture;
    const toolName = actionRecord.tool_name || "";
    const allowedTools = agentPosture.allowedTools || [];

    // 如果 allowedTools 为空 = 允许所有
    if (allowedTools.length === 0) return 0;

    // 工具不在允许列表中
    if (!allowedTools.includes(toolName)) {
      return 0.8; // 高风险：超出授权
    }

    return 0;
  }

  /**
   * 维度 3：数据敏感度评估
   * 检查本步骤接触的数据分类等级
   * @private
   */
  _assessDataSensitivity(actionRecord) {
    const patterns = this.config.sensitiveDataPatterns;
    const inputStr = JSON.stringify(actionRecord.input || {});
    const outputStr = JSON.stringify(actionRecord.output || {});
    const combined = inputStr + outputStr;

    let maxScore = 0;
    for (const { pattern, level } of patterns) {
      if (pattern.test(combined)) {
        const score =
          level === "critical" ? 1.0 : level === "high" ? 0.7 : 0.3;
        if (score > maxScore) maxScore = score;
      }
    }
    return maxScore;
  }

  /**
   * 维度 4：跨系统边界跳跃评估
   * 检查是否从一个安全域跳到另一个
   * @private
   */
  _assessBoundaryCrossing(actionRecord, sessionId) {
    const currentTool = actionRecord.tool_name || "";
    const previousTool = this.lastActionTool.get(sessionId) || "";

    if (!previousTool || !currentTool) return 0;

    // 定义安全域分类
    const domains = {
      internal: /^(read|query|get|list|search|fetch)/i,
      external: /^(send|post|put|http|api|webhook|publish)/i,
      execution: /^(exec|run|terminal|command|shell|code)/i,
      storage: /^(write|save|store|database|db|file)/i,
    };

    const prevDomain = this._classifyDomain(previousTool, domains);
    const currDomain = this._classifyDomain(currentTool, domains);

    // 跨域跳跃
    if (prevDomain && currDomain && prevDomain !== currDomain) {
      // 从 internal 跳到 external/execution 风险更高
      if (prevDomain === "internal" && (currDomain === "external" || currDomain === "execution")) {
        return 0.7;
      }
      return 0.4;
    }
    return 0;
  }

  /**
   * 分类工具所属安全域
   * @private
   */
  _classifyDomain(toolName, domains) {
    for (const [domain, pattern] of Object.entries(domains)) {
      if (pattern.test(toolName)) return domain;
    }
    return null;
  }

  /**
   * 维度 5：行为漂移评估
   * 与 Agent 历史行为基线对比
   * @private
   */
  _assessBehavioralDrift(actionRecord) {
    const agentId = actionRecord.agent_id;
    const toolName = actionRecord.tool_name || "";
    if (!agentId || !toolName) return 0;

    const baseline = this.agentBaselines.get(agentId) || [];

    // 基线太少，无法判断漂移
    if (baseline.length < 5) return 0;

    // 检查当前工具是否在历史基线中出现过
    const toolFrequency = baseline.filter((t) => t === toolName).length;
    const ratio = toolFrequency / baseline.length;

    // 从未用过的工具 → 高漂移分
    if (ratio === 0) return 0.6;
    // 很少用的工具
    if (ratio < 0.05) return 0.3;

    return 0;
  }

  /**
   * 更新 Agent 行为基线
   * @private
   */
  _updateBaseline(actionRecord) {
    const agentId = actionRecord.agent_id;
    const toolName = actionRecord.tool_name;
    if (!agentId || !toolName) return;

    if (!this.agentBaselines.has(agentId)) {
      this.agentBaselines.set(agentId, []);
    }
    const baseline = this.agentBaselines.get(agentId);
    baseline.push(toolName);

    // 保持基线在合理大小
    if (baseline.length > 1000) {
      baseline.splice(0, baseline.length - 500);
    }
  }

  /**
   * 清理过期 session 数据
   * @param {string} sessionId
   */
  evictSession(sessionId) {
    this.sessionScores.delete(sessionId);
    this.lastActionTool.delete(sessionId);
  }
}
