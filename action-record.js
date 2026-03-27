/**
 * action-record.js — Action Record 构建与管理
 *
 * 每次 tool 调用或 LLM 推理产生一条 Action Record，
 * 同时携带执行链 ID + 数据血缘 ID + 污点标记 + 风险快照。
 */

// ── ActionRecordBuilder ──────────────────────────────────────────────────────

export class ActionRecordBuilder {
  /**
   * 从工具调用构建 Action Record
   *
   * @param {object} params
   * @param {string} params.agentId      - agent_id
   * @param {string} params.sessionId    - session_id
   * @param {string} params.turnId       - turn_id
   * @param {string} params.actionId     - action_id
   * @param {string|null} params.parentActionId  - 父 action_id（跨 Agent 委派）
   * @param {string|null} params.parentAgentId   - 委派方 agent_id
   * @param {string} params.toolName     - 工具名称
   * @param {object} params.input        - 工具输入参数
   * @param {object} [params.output]     - 工具输出结果（after_tool_call 时填充）
   * @param {number} [params.durationMs] - 执行时长
   * @param {string[]} params.dataInputs - 消费的 data_id 列表
   * @param {string[]} params.dataOutputs - 产生的 data_id 列表
   * @param {object} params.taint        - 污点信息
   * @param {object} params.risk         - 风险快照
   * @returns {object} 完整 Action Record
   */
  static buildFromToolCall({
    agentId,
    sessionId,
    turnId,
    actionId,
    parentActionId = null,
    parentAgentId = null,
    toolName,
    input,
    output,
    durationMs,
    dataInputs = [],
    dataOutputs = [],
    taint = {},
    risk = {},
  }) {
    return {
      // ── 执行链 ID ──
      agent_id: agentId,
      session_id: sessionId,
      turn_id: turnId,
      action_id: actionId,

      // ── 父子关系 ──
      parent_action_id: parentActionId,
      parent_agent_id: parentAgentId,

      // ── 执行内容 ──
      action_type: "tool_call",
      tool_name: toolName,
      input: input ?? null,
      output: output ?? null,
      timestamp: new Date().toISOString(),
      duration_ms: durationMs ?? null,

      // ── 数据血缘链 ──
      data_inputs: dataInputs,
      data_outputs: dataOutputs,

      // ── 污点标记 ──
      taint: {
        inherited_from: taint.inheritedFrom || [],
        taint_level: taint.outputTaintLevel || "trusted",
        taint_source: taint.taintSource || "none",
      },

      // ── 风险快照 ──
      risk: {
        cumulative_score: risk.cumulativeScore ?? 0,
        delta: risk.delta ?? 0,
        flags: risk.flags || [],
      },
    };
  }

  /**
   * 从 LLM 推理构建 Action Record
   *
   * @param {object} params
   * @param {string} params.agentId
   * @param {string} params.sessionId
   * @param {string} params.turnId
   * @param {string} params.actionId
   * @param {string|null} params.parentActionId
   * @param {string|null} params.parentAgentId
   * @param {string} [params.model]
   * @param {string} [params.provider]
   * @param {object} [params.input]
   * @param {object} [params.output]
   * @param {number} [params.durationMs]
   * @param {string[]} params.dataInputs
   * @param {string[]} params.dataOutputs
   * @param {object} params.taint
   * @param {object} params.risk
   * @returns {object} 完整 Action Record
   */
  static buildFromLLMInference({
    agentId,
    sessionId,
    turnId,
    actionId,
    parentActionId = null,
    parentAgentId = null,
    model,
    provider,
    input,
    output,
    durationMs,
    dataInputs = [],
    dataOutputs = [],
    taint = {},
    risk = {},
  }) {
    return {
      // ── 执行链 ID ──
      agent_id: agentId,
      session_id: sessionId,
      turn_id: turnId,
      action_id: actionId,

      // ── 父子关系 ──
      parent_action_id: parentActionId,
      parent_agent_id: parentAgentId,

      // ── 执行内容 ──
      action_type: "llm_inference",
      tool_name: null,
      model: model ?? null,
      provider: provider ?? null,
      input: input ?? null,
      output: output ?? null,
      timestamp: new Date().toISOString(),
      duration_ms: durationMs ?? null,

      // ── 数据血缘链 ──
      data_inputs: dataInputs,
      data_outputs: dataOutputs,

      // ── 污点标记 ──
      taint: {
        inherited_from: taint.inheritedFrom || [],
        taint_level: taint.outputTaintLevel || "trusted",
        taint_source: taint.taintSource || "none",
      },

      // ── 风险快照 ──
      risk: {
        cumulative_score: risk.cumulativeScore ?? 0,
        delta: risk.delta ?? 0,
        flags: risk.flags || [],
      },
    };
  }

  /**
   * 将 Action Record 的追踪信息提取为 Langfuse metadata 格式
   * @param {object} actionRecord
   * @returns {object} 可嵌入 Langfuse span metadata 的 tracking 对象
   */
  static toTrackingMetadata(actionRecord) {
    return {
      tracking: {
        agent_id: actionRecord.agent_id,
        session_id: actionRecord.session_id,
        turn_id: actionRecord.turn_id,
        action_id: actionRecord.action_id,
        parent_action_id: actionRecord.parent_action_id,
        parent_agent_id: actionRecord.parent_agent_id,
        action_type: actionRecord.action_type,
        data_inputs: actionRecord.data_inputs,
        data_outputs: actionRecord.data_outputs,
        taint: actionRecord.taint,
        risk: actionRecord.risk,
      },
    };
  }
}
