/**
 * data-lineage.js — 数据血缘追踪
 *
 * 核心职责：
 * - 为每条数据分配 data_id 并注册到全局注册表
 * - 记录数据转换关系（data_inputs → data_outputs）
 * - 支持正向/反向血缘遍历（从任意 data_id 还原完整血缘图）
 * - data_id 跟着数据走，不管经过几个 Agent / Session
 */

import { dataId as genDataId } from "./id-generator.js";

// ── 数据记录结构 ─────────────────────────────────────────────────────────────

/**
 * @typedef {Object} DataRecord
 * @property {string} dataId          - 数据唯一标识
 * @property {string} source          - 数据来源分类 (user_input, llm_output, tool_output, external_api, etc.)
 * @property {string} taintLevel      - 污点级别 (untrusted | mixed | trusted)
 * @property {string} taintSource     - 污染源分类
 * @property {string[]} inheritedFrom - 污点继承自哪些 data_id
 * @property {string} createdAt       - 创建时间 ISO
 * @property {string} createdByAction - 创建该数据的 action_id
 * @property {string} createdByAgent  - 创建该数据的 agent_id
 */

/**
 * @typedef {Object} TransformRecord
 * @property {string} actionId        - 执行转换的 action_id
 * @property {string[]} inputs        - 消费的 data_id 列表
 * @property {string[]} outputs       - 产生的 data_id 列表
 * @property {string} timestamp       - 转换时间 ISO
 */

// ── DataLineageTracker ───────────────────────────────────────────────────────

export class DataLineageTracker {
  constructor() {
    /** @type {Map<string, DataRecord>} data_id → DataRecord */
    this.dataRegistry = new Map();

    /** @type {TransformRecord[]} 所有转换记录（有序） */
    this.transforms = [];

    /** @type {Map<string, string[]>} data_id → 由它产生的子 data_id 列表（正向图） */
    this.forwardEdges = new Map();

    /** @type {Map<string, string[]>} data_id → 它由哪些 data_id 产生（反向图） */
    this.backwardEdges = new Map();
  }

  /**
   * 注册新数据并分配 data_id
   * @param {object} params
   * @param {string} params.source - 来源分类
   * @param {string} params.taintLevel - 初始污点级别
   * @param {string} [params.taintSource] - 污染源分类
   * @param {string[]} [params.inheritedFrom] - 继承的 data_id 列表
   * @param {string} [params.actionId] - 创建该数据的 action_id
   * @param {string} [params.agentId] - 创建该数据的 agent_id
   * @returns {string} 新生成的 data_id
   */
  registerData({ source, taintLevel, taintSource, inheritedFrom, actionId, agentId }) {
    const id = genDataId();
    /** @type {DataRecord} */
    const record = {
      dataId: id,
      source: source || "unknown",
      taintLevel: taintLevel || "untrusted",
      taintSource: taintSource || source || "unknown",
      inheritedFrom: inheritedFrom || [],
      createdAt: new Date().toISOString(),
      createdByAction: actionId || null,
      createdByAgent: agentId || null,
    };
    this.dataRegistry.set(id, record);
    return id;
  }

  /**
   * 获取数据记录
   * @param {string} dataId
   * @returns {DataRecord|undefined}
   */
  getData(dataId) {
    return this.dataRegistry.get(dataId);
  }

  /**
   * 获取数据的污点级别
   * @param {string} dataId
   * @returns {string} taintLevel
   */
  getTaintLevel(dataId) {
    const record = this.dataRegistry.get(dataId);
    return record ? record.taintLevel : "untrusted";
  }

  /**
   * 更新数据的污点信息
   * @param {string} dataId
   * @param {string} taintLevel
   * @param {string[]} inheritedFrom
   * @param {string} taintSource
   */
  updateTaint(dataId, taintLevel, inheritedFrom, taintSource) {
    const record = this.dataRegistry.get(dataId);
    if (record) {
      record.taintLevel = taintLevel;
      record.inheritedFrom = inheritedFrom;
      record.taintSource = taintSource;
    }
  }

  /**
   * 记录数据转换：action 消费 inputs 产生 outputs
   * 同时构建正向/反向图边
   * @param {string} actionId
   * @param {string[]} inputDataIds - 输入 data_id 列表
   * @param {string[]} outputDataIds - 输出 data_id 列表
   */
  recordTransform(actionId, inputDataIds, outputDataIds) {
    const transform = {
      actionId,
      inputs: inputDataIds || [],
      outputs: outputDataIds || [],
      timestamp: new Date().toISOString(),
    };
    this.transforms.push(transform);

    // 构建 DAG 边
    for (const inId of transform.inputs) {
      for (const outId of transform.outputs) {
        // 正向：input → output
        if (!this.forwardEdges.has(inId)) {
          this.forwardEdges.set(inId, []);
        }
        this.forwardEdges.get(inId).push(outId);

        // 反向：output ← input
        if (!this.backwardEdges.has(outId)) {
          this.backwardEdges.set(outId, []);
        }
        this.backwardEdges.get(outId).push(inId);
      }
    }
  }

  /**
   * 正向血缘遍历：给定 data_id，找出它影响的所有下游数据
   * @param {string} dataId
   * @returns {string[]} 所有下游 data_id（BFS）
   */
  getForwardLineage(dataId) {
    return this._bfs(dataId, this.forwardEdges);
  }

  /**
   * 反向血缘遍历：给定 data_id，找出它的所有上游数据源
   * @param {string} dataId
   * @returns {string[]} 所有上游 data_id（BFS）
   */
  getBackwardLineage(dataId) {
    return this._bfs(dataId, this.backwardEdges);
  }

  /**
   * 获取完整血缘信息
   * @param {string} dataId
   * @returns {{ data: DataRecord, upstream: string[], downstream: string[] }}
   */
  getLineage(dataId) {
    return {
      data: this.dataRegistry.get(dataId) || null,
      upstream: this.getBackwardLineage(dataId),
      downstream: this.getForwardLineage(dataId),
    };
  }

  /**
   * BFS 遍历图
   * @private
   */
  _bfs(startId, edges) {
    const visited = new Set();
    const queue = [startId];
    const result = [];

    while (queue.length > 0) {
      const current = queue.shift();
      const neighbors = edges.get(current) || [];
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          result.push(neighbor);
          queue.push(neighbor);
        }
      }
    }
    return result;
  }

  /**
   * 清理过期数据（防内存泄漏）
   * @param {number} maxAge - 最大存活时间（毫秒）
   */
  evict(maxAge) {
    const cutoff = Date.now() - maxAge;
    for (const [id, record] of this.dataRegistry) {
      if (new Date(record.createdAt).getTime() < cutoff) {
        this.dataRegistry.delete(id);
        this.forwardEdges.delete(id);
        this.backwardEdges.delete(id);
      }
    }
  }
}
