/**
 * beam-intervention.js — Beam 干预机制
 *
 * 支持两种模式：
 * - passive: 仅记录告警到 metadata，不阻止任何操作
 * - active: 返回干预指令（注入上下文提示 / 阻止执行）
 *
 * Beam 干预在以下场景触发：
 * 1. 累积风险分超过阈值
 * 2. 被污染数据到达 Sink 操作
 * 3. 权限升级检测
 */

// ── 干预类型 ─────────────────────────────────────────────────────────────────

export const INTERVENTION_TYPES = {
  CONTEXT_INJECT: "context_inject",   // 注入额外上下文提示
  BLOCK: "block",                      // 阻止执行
  WARN: "warn",                        // 仅告警记录
};

// ── BeamIntervenor ───────────────────────────────────────────────────────────

export class BeamIntervenor {
  /**
   * @param {object} config - 完整配置
   */
  constructor(config) {
    this.config = config;
    /** @type {Map<string, Array>} session_id → 干预历史 */
    this.interventionHistory = new Map();
  }

  /**
   * 评估是否需要干预，并返回干预决定
   *
   * @param {object} params
   * @param {string} params.sessionId - 当前 session_id
   * @param {object} params.actionRecord - 当前 action record
   * @param {number} params.cumulativeScore - 当前累积风险分
   * @param {object|null} params.sinkAlert - Sink 告警（来自 TaintEngine）
   * @returns {{ shouldIntervene: boolean, intervention: object|null }}
   */
  evaluate({ sessionId, actionRecord, cumulativeScore, sinkAlert }) {
    const mode = this.config.mode;
    const threshold = this.config.risk.beamThreshold;
    const interventions = [];

    // ── 检查 1：累积风险超阈值 ──
    if (cumulativeScore >= threshold) {
      interventions.push({
        type: mode === "active" ? INTERVENTION_TYPES.CONTEXT_INJECT : INTERVENTION_TYPES.WARN,
        reason: "cumulative_risk_exceeded",
        message: this.config.beamMessages.highRisk,
        score: cumulativeScore,
        threshold,
      });
    }

    // ── 检查 2：被污染数据到达 Sink ──
    if (sinkAlert) {
      interventions.push({
        type: mode === "active" ? INTERVENTION_TYPES.BLOCK : INTERVENTION_TYPES.WARN,
        reason: "tainted_data_at_sink",
        message: this.config.beamMessages.taintedSink,
        alert: sinkAlert,
      });
    }

    // ── 检查 3：单步风险增量过高 ──
    const delta = actionRecord.risk?.delta ?? 0;
    if (delta >= this.config.risk.deltaAlertThreshold) {
      interventions.push({
        type: mode === "active" ? INTERVENTION_TYPES.CONTEXT_INJECT : INTERVENTION_TYPES.WARN,
        reason: "high_risk_delta",
        message: `Risk delta ${delta} exceeds alert threshold ${this.config.risk.deltaAlertThreshold}`,
        delta,
      });
    }

    // ── 检查 4：权限升级 ──
    const flags = actionRecord.risk?.flags || [];
    if (flags.includes("privilege_escalation")) {
      interventions.push({
        type: mode === "active" ? INTERVENTION_TYPES.BLOCK : INTERVENTION_TYPES.WARN,
        reason: "privilege_escalation",
        message: this.config.beamMessages.privilegeEscalation,
      });
    }

    if (interventions.length === 0) {
      return { shouldIntervene: false, intervention: null };
    }

    // 选择最严重的干预
    const severityOrder = [
      INTERVENTION_TYPES.BLOCK,
      INTERVENTION_TYPES.CONTEXT_INJECT,
      INTERVENTION_TYPES.WARN,
    ];
    interventions.sort(
      (a, b) => severityOrder.indexOf(a.type) - severityOrder.indexOf(b.type)
    );

    const primaryIntervention = {
      ...interventions[0],
      allReasons: interventions.map((i) => i.reason),
      timestamp: new Date().toISOString(),
      actionId: actionRecord.action_id,
      sessionId,
    };

    // 记录干预历史
    this._recordIntervention(sessionId, primaryIntervention);

    return {
      shouldIntervene: true,
      intervention: primaryIntervention,
    };
  }

  /**
   * 获取 session 的干预历史
   * @param {string} sessionId
   * @returns {Array}
   */
  getInterventionHistory(sessionId) {
    return this.interventionHistory.get(sessionId) || [];
  }

  /**
   * 获取所有干预统计
   * @returns {{ totalInterventions: number, byType: object, byReason: object }}
   */
  getStats() {
    let total = 0;
    const byType = {};
    const byReason = {};

    for (const history of this.interventionHistory.values()) {
      for (const intervention of history) {
        total++;
        byType[intervention.type] = (byType[intervention.type] || 0) + 1;
        for (const reason of intervention.allReasons || [intervention.reason]) {
          byReason[reason] = (byReason[reason] || 0) + 1;
        }
      }
    }

    return { totalInterventions: total, byType, byReason };
  }

  /**
   * 构建干预后注入的上下文消息（active 模式使用）
   * @param {object} intervention
   * @returns {string} 可注入到 Agent 上下文中的提示文本
   */
  buildContextMessage(intervention) {
    const lines = [
      `[BEAM INTERVENTION — ${intervention.reason}]`,
      intervention.message,
    ];

    if (intervention.alert) {
      const tainted = intervention.alert.taintedInputs || [];
      if (tainted.length > 0) {
        lines.push(`Tainted data IDs: ${tainted.map((t) => t.dataId).join(", ")}`);
        lines.push(`Taint levels: ${tainted.map((t) => t.taintLevel).join(", ")}`);
      }
    }

    if (intervention.score != null) {
      lines.push(`Cumulative risk score: ${intervention.score.toFixed(3)} (threshold: ${intervention.threshold})`);
    }

    return lines.join("\n");
  }

  // ── 私有方法 ───────────────────────────────────────────────────────────────

  /**
   * 记录干预到历史
   * @private
   */
  _recordIntervention(sessionId, intervention) {
    if (!this.interventionHistory.has(sessionId)) {
      this.interventionHistory.set(sessionId, []);
    }
    const history = this.interventionHistory.get(sessionId);
    history.push(intervention);

    // 限制历史长度
    if (history.length > 500) {
      history.splice(0, history.length - 250);
    }
  }

  /**
   * 清理过期 session 数据
   * @param {string} sessionId
   */
  evictSession(sessionId) {
    this.interventionHistory.delete(sessionId);
  }
}
