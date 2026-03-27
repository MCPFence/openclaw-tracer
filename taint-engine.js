/**
 * taint-engine.js — 污点传播引擎
 *
 * 核心职责：
 * - 根据输入数据的污点级别计算输出数据的污点级别
 * - 检测被污染数据到达 Sink 操作的情况
 * - 沿 data_id 链反向追踪完整污点继承链
 *
 * 污点级别: untrusted > mixed > trusted
 * 传播规则: 只要有一个输入是 untrusted，输出就标记为 mixed
 *          所有输入都 trusted，输出才 trusted
 */

// ── 污点级别常量 ─────────────────────────────────────────────────────────────

export const TAINT_LEVELS = {
  UNTRUSTED: "untrusted",
  MIXED: "mixed",
  TRUSTED: "trusted",
};

/** 污点严重度排序（数值越高越严重） */
const TAINT_SEVERITY = {
  trusted: 0,
  mixed: 1,
  untrusted: 2,
};

// ── TaintEngine ──────────────────────────────────────────────────────────────

export class TaintEngine {
  /**
   * @param {import('./data-lineage.js').DataLineageTracker} lineageTracker
   * @param {object} config - 完整配置
   */
  constructor(lineageTracker, config) {
    this.lineage = lineageTracker;
    this.config = config;
    /** @type {Array<{actionId: string, dataId: string, taintLevel: string, sink: string, timestamp: string}>} */
    this.sinkAlerts = [];
  }

  /**
   * 对一次 action 执行污点传播
   *
   * 读取 action 的所有输入 data_id 的污点级别，
   * 计算输出 data_id 应继承的污点级别，
   * 并更新 lineage tracker 中的记录。
   *
   * @param {object} actionRecord - 包含 data_inputs, data_outputs, action_id 等字段
   * @returns {{ outputTaintLevel: string, inheritedFrom: string[], taintSource: string }}
   */
  propagateTaint(actionRecord) {
    const inputIds = actionRecord.data_inputs || [];
    const outputIds = actionRecord.data_outputs || [];

    if (inputIds.length === 0) {
      // 没有输入 = 新数据源，沿用其注册时的污点
      return {
        outputTaintLevel: TAINT_LEVELS.TRUSTED,
        inheritedFrom: [],
        taintSource: "none",
      };
    }

    // 收集所有输入的污点信息
    const inputTaints = inputIds.map((id) => {
      const record = this.lineage.getData(id);
      return {
        dataId: id,
        level: record ? record.taintLevel : TAINT_LEVELS.UNTRUSTED,
        source: record ? record.taintSource : "unknown",
      };
    });

    // 传播规则：取最高污点级别
    let maxSeverity = 0;
    const sources = new Set();
    const inheritedFrom = [];

    for (const t of inputTaints) {
      const severity = TAINT_SEVERITY[t.level] ?? 2;
      if (severity > maxSeverity) maxSeverity = severity;
      sources.add(t.source);
      inheritedFrom.push(t.dataId);
    }

    // 计算输出污点级别
    let outputTaintLevel;
    if (maxSeverity >= 2) {
      // 存在 untrusted 输入
      // 如果还有 trusted 输入混合 → mixed；全 untrusted → 仍标 mixed（经过处理了）
      const hasTrusted = inputTaints.some(
        (t) => TAINT_SEVERITY[t.level] === 0
      );
      outputTaintLevel = hasTrusted
        ? TAINT_LEVELS.MIXED
        : TAINT_LEVELS.UNTRUSTED;
    } else if (maxSeverity >= 1) {
      // 存在 mixed 但无 untrusted
      outputTaintLevel = TAINT_LEVELS.MIXED;
    } else {
      // 全部 trusted
      outputTaintLevel = TAINT_LEVELS.TRUSTED;
    }

    const taintSource = [...sources].join("+");

    // 更新所有输出数据的污点
    for (const outId of outputIds) {
      this.lineage.updateTaint(outId, outputTaintLevel, inheritedFrom, taintSource);
    }

    return { outputTaintLevel, inheritedFrom, taintSource };
  }

  /**
   * 检查是否有被污染的数据到达 Sink 操作
   *
   * @param {object} actionRecord - 完整 action record
   * @returns {{ isSink: boolean, alert: object|null }}
   */
  checkSink(actionRecord) {
    const toolName = actionRecord.tool_name || "";
    const actionType = actionRecord.action_type || "";

    // 判断是否为 Sink
    const isSinkByType = this.config.sinkTypes.includes(actionType);
    const isSinkByTool = this.config.sinkToolPatterns.some((pattern) =>
      pattern.test(toolName)
    );

    if (!isSinkByType && !isSinkByTool) {
      return { isSink: false, alert: null };
    }

    // 检查输入数据的污点
    const inputIds = actionRecord.data_inputs || [];
    const taintedInputs = [];

    for (const id of inputIds) {
      const record = this.lineage.getData(id);
      if (record && record.taintLevel !== TAINT_LEVELS.TRUSTED) {
        taintedInputs.push({
          dataId: id,
          taintLevel: record.taintLevel,
          taintSource: record.taintSource,
        });
      }
    }

    if (taintedInputs.length === 0) {
      return { isSink: true, alert: null }; // 是 Sink 但数据干净
    }

    // 告警：被污染数据到达 Sink
    const alert = {
      type: "tainted_data_at_sink",
      actionId: actionRecord.action_id,
      toolName,
      actionType,
      taintedInputs,
      taintChain: taintedInputs.map((t) => ({
        dataId: t.dataId,
        chain: this.traceTaintChain(t.dataId),
      })),
      timestamp: new Date().toISOString(),
    };

    this.sinkAlerts.push({
      actionId: actionRecord.action_id,
      dataId: taintedInputs[0].dataId,
      taintLevel: taintedInputs[0].taintLevel,
      sink: toolName || actionType,
      timestamp: alert.timestamp,
    });

    return { isSink: true, alert };
  }

  /**
   * 反向追踪完整污点继承链
   *
   * @param {string} dataId - 起始 data_id
   * @returns {Array<{ dataId: string, taintLevel: string, source: string }>}
   */
  traceTaintChain(dataId) {
    const chain = [];
    const visited = new Set();
    const queue = [dataId];

    while (queue.length > 0) {
      const current = queue.shift();
      if (visited.has(current)) continue;
      visited.add(current);

      const record = this.lineage.getData(current);
      if (record) {
        chain.push({
          dataId: current,
          taintLevel: record.taintLevel,
          source: record.taintSource,
        });
        // 沿 inheritedFrom 继续追踪
        for (const parentId of record.inheritedFrom || []) {
          if (!visited.has(parentId)) {
            queue.push(parentId);
          }
        }
      }
    }

    return chain;
  }

  /**
   * 评估本次 action 的污点严重度分数 (0.0 ~ 1.0)
   *
   * @param {object} actionRecord
   * @returns {number}
   */
  assessTaintSeverity(actionRecord) {
    const inputIds = actionRecord.data_inputs || [];
    if (inputIds.length === 0) return 0;

    let maxSeverity = 0;
    for (const id of inputIds) {
      const level = this.lineage.getTaintLevel(id);
      const s = TAINT_SEVERITY[level] ?? 0;
      if (s > maxSeverity) maxSeverity = s;
    }

    // 归一化到 0~1
    // untrusted=2 → 1.0, mixed=1 → 0.5, trusted=0 → 0.0
    const base = maxSeverity / 2;

    // Sink 加成
    const { isSink, alert } = this.checkSink(actionRecord);
    const sinkMultiplier = alert ? 1.5 : isSink ? 1.2 : 1.0;

    return Math.min(base * sinkMultiplier, 1.0);
  }

  /**
   * 获取所有 Sink 告警
   * @returns {Array}
   */
  getAlerts() {
    return this.sinkAlerts;
  }
}
