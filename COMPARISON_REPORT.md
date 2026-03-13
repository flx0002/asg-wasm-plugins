# Google ADK vs ai-context-manager 上下文管理功能对比报告

## 概述

本报告对比了 Google ADK（Agent Development Kit）的上下文管理功能模块与本项目 `ai-context-manager` 插件的功能覆盖情况，并记录了已实施的改进。

## 功能对比矩阵

| 功能模块 | Google ADK | ai-context-manager (改进前) | ai-context-manager (改进后) | 状态 |
|--------|-----------|-------------------------|-------------------------|------|
| **上下文压缩/紧凑化** | ✅ EventsCompactionConfig | ❌ 缺失 | ✅ compaction 策略 | 🆕 新增 |
| **压缩间隔触发** | ✅ compaction_interval | ❌ 缺失 | ✅ compaction_interval | 🆕 新增 |
| **重叠窗口** | ✅ overlap_size | ❌ 缺失 | ✅ overlap_size | 🆕 新增 |
| **Token 阈值触发** | ✅ token_threshold | ❌ 缺失 | ✅ token_threshold | 🆕 新增 |
| **摘要模板自定义** | ✅ 自定义 summarizer | ❌ 缺失 | ✅ compaction_summary_template | 🆕 新增 |
| **作用域状态管理** | ✅ session/user/app/temp 前缀 | ❌ 缺失 | ✅ state_scope + state_header_prefix | 🆕 新增 |
| **滑动窗口** | ✅ 作为压缩的底层机制 | ✅ sliding_window 策略 | ✅ 保留原有功能 | ✅ 已有 |
| **消息数量限制** | ⚠️ 间接支持 | ✅ max_messages | ✅ 保留原有功能 | ✅ 已有 |
| **Token 数量限制** | ⚠️ 间接支持 | ✅ max_tokens | ✅ 保留原有功能 | ✅ 已有 |
| **系统消息保护** | ✅ 系统指令不被压缩 | ✅ preserve_system_message | ✅ 保留原有功能 | ✅ 已有 |
| **最近消息保留** | ✅ 保留最近事件 | ✅ preserve_last_n | ✅ 保留原有功能 | ✅ 已有 |
| **截断策略** | ⚠️ 不推荐（信息丢失） | ✅ truncate 策略 | ✅ 保留原有功能 | ✅ 已有 |
| **会话记忆注入** | ✅ session.state | ✅ inject_memory | ✅ 保留原有功能 | ✅ 已有 |
| **LLM 生成摘要** | ✅ 通过 LLM API 调用 | ❌ 不适用（网关层） | ⚠️ 使用提取式摘要（见说明） | ⚠️ 差异 |
| **会话持久化后端** | ✅ InMemory/DB/Vertex AI | ❌ 不适用（无状态网关） | ❌ 不适用（无状态网关） | ➖ 不适用 |
| **会话恢复** | ✅ 流式断线重连 | ❌ 不适用 | ❌ 不适用 | ➖ 不适用 |

## 详细对比

### 1. 上下文压缩/紧凑化（Context Compaction）

**Google ADK 实现：**
```python
from google.adk.apps.app import App, EventsCompactionConfig

app = App(
    name="my-agent",
    root_agent=root_agent,
    events_compaction_config=EventsCompactionConfig(
        compaction_interval=3,
        overlap_size=1
    ),
)
```
- 使用 LLM 对历史事件进行摘要
- 在 Agent 应用层面配置
- 支持按事件间隔或 Token 阈值触发

**ai-context-manager 实现：**
```yaml
summarize_strategy: compaction
compaction_interval: 3
overlap_size: 1
token_threshold: 2000
compaction_summary_template: "[Context Summary]\n{summary}"
```
- 使用提取式摘要（提取关键信息，不调用 LLM）
- 在 API 网关层面配置
- 支持按对话轮次、Token 阈值、消息数量等多种触发条件
- 适合高性能网关场景，无额外 LLM 调用开销

**差异说明：**
Google ADK 使用 LLM 生成自然语言摘要，压缩质量更高但需要额外 API 调用。
ai-context-manager 使用提取式摘要，在网关层零延迟处理，适合高吞吐场景。
如需 LLM 生成摘要，建议结合 ai-proxy 插件实现两阶段处理。

### 2. 压缩间隔（Compaction Interval）

**Google ADK：** `compaction_interval` - 按事件数量（用户/Agent 消息）触发
**ai-context-manager：** `compaction_interval` - 按对话轮次（用户消息数）触发

两者语义一致，ai-context-manager 以用户消息数作为轮次计数。

### 3. 重叠窗口（Overlap Size）

**Google ADK：** `overlap_size` - 保留最近 N 个事件与摘要重叠，确保上下文连续性
**ai-context-manager：** `overlap_size` - 保留最近 N 条消息不被压缩

语义完全一致。Google ADK 在摘要中包含重叠事件用于连续性，ai-context-manager 直接保留这些消息。

### 4. Token 阈值（Token Threshold）

**Google ADK：** 支持通过 `token_threshold` 替代 `compaction_interval` 触发压缩
**ai-context-manager：** `token_threshold` - 当总 Token 数超过阈值时触发压缩

两者功能一致。ai-context-manager 还额外支持同时配置多种触发条件。

### 5. 作用域状态管理（Scoped State）

**Google ADK：**
- `session.state['key']` - 会话级状态
- `session.state['user:key']` - 用户级状态（跨会话）
- `session.state['app:key']` - 应用级状态（全局）
- `session.state['temp:key']` - 临时状态（单次调用）

**ai-context-manager：**
- `state_scope: "session"` - 会话级
- `state_scope: "user"` - 用户级
- `state_scope: "app"` - 应用级
- `state_scope: "temp"` - 临时
- 通过 `{state_header_prefix}-{scope}` 请求头传递状态

作为无状态网关插件，ai-context-manager 通过请求头机制实现了类似的作用域概念，实际状态持久化由上游服务负责。

### 6. 不适用的功能

以下 Google ADK 功能由于架构差异不适用于网关插件场景：

| 功能 | 原因 |
|------|------|
| **会话持久化后端** | 网关是无状态的，持久化由上游会话管理服务负责 |
| **会话恢复** | 属于客户端/Agent SDK 层面功能 |
| **LLM 生成摘要** | 网关层需要零延迟处理，LLM 调用不适合同步处理（可通过插件组合实现） |
| **Multi-Agent 编排** | 属于 Agent Framework 层面功能，不属于网关职责 |

## 改进总结

### 新增功能（6 项）

1. **compaction 策略** - 上下文压缩/紧凑化，将较早消息压缩为摘要消息
2. **compaction_interval** - 按对话轮次间隔触发压缩
3. **overlap_size** - 压缩窗口间的重叠消息保留
4. **token_threshold** - Token 数量阈值触发压缩
5. **compaction_summary_template** - 可自定义的摘要消息模板
6. **作用域状态管理** - session/user/app/temp 前缀支持

### 新增测试（18 个测试用例）

- `TestParseConfigCompaction` - 压缩配置解析（4 个子测试）
- `TestCountConversationTurns` - 对话轮次计数（3 个子测试）
- `TestEstimateTotalTokens` - 总 Token 估算（2 个子测试）
- `TestShouldCompact` - 压缩触发判断（5 个子测试）
- `TestCompactMessages` - 消息压缩（4 个子测试）
- `TestApplyCompactionStrategy` - 压缩策略应用（6 个子测试）
- `TestManageContextWithCompaction` - 压缩策略集成（2 个子测试）
- `TestBuildScopeKey` - 作用域键构建（4 个子测试）
- `TestOnHttpRequestBodyCompaction` - 端到端压缩测试（1 个子测试）

### 保留的原有功能

所有原有功能（sliding_window、truncate、消息/Token 限制、系统消息保护、记忆注入等）完全保留，所有原有测试继续通过。

## 建议

1. **生产环境推荐配置**：使用 `compaction` 策略配合 `compaction_interval: 3-5` 和 `overlap_size: 1-2`
2. **高级 LLM 摘要**：如需 LLM 生成的高质量摘要，建议将 ai-context-manager 与 ai-proxy 插件组合使用，实现两阶段处理
3. **状态持久化**：将 ai-context-manager 与 ai-history 插件配合使用，实现完整的会话状态管理
