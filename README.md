---
title: AI 上下文管理
keywords: [ AI网关, 上下文管理, 记忆管理, 上下文压缩 ]
description: AI 上下文管理和记忆管理插件配置参考
---

## 功能说明

AI 上下文管理插件，用于管理 LLM 对话的上下文窗口，参考 Google ADK（Agent Development Kit）设计，支持：
- 消息数量限制
- Token 数量估算和限制
- 系统提示词保护
- 滑动窗口策略
- **上下文压缩/紧凑化策略**（参考 Google ADK EventsCompactionConfig）
- **紧凑化间隔触发**（按对话轮次触发压缩）
- **Token 阈值触发**（按 Token 数量触发压缩）
- **重叠窗口**（压缩边界处保留消息以维持上下文连续性）
- **可自定义摘要模板**
- **作用域状态管理**（session/user/app/temp 前缀，参考 ADK State 管理）
- 会话记忆注入

## 运行属性

插件执行阶段：`默认阶段`
插件执行优先级：`500`

## 配置说明

### 基础配置

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|----------------|-----------------|------|-----|----------------------------------|
| `max_messages` | int | 选填 | 0 (无限制) | 上下文最大消息数量 |
| `max_tokens` | int | 选填 | 0 (无限制) | 上下文最大 Token 数量（估算） |
| `preserve_system_message` | bool | 选填 | true | 是否保留系统提示词 |
| `preserve_last_n` | int | 选填 | 2 | 强制保留最近 N 条消息 |
| `summarize_strategy` | string | 选填 | "sliding_window" | 上下文管理策略，可选 "truncate"、"sliding_window" 或 "compaction" |
| `token_estimate_ratio` | float | 选填 | 4.0 | Token 估算比率（字符数/Token） |
| `memory_key` | string | 选填 | "x-session-memory" | 会话记忆的请求头键名 |
| `inject_memory` | bool | 选填 | false | 是否注入会话记忆 |

### 上下文压缩配置（Google ADK 风格）

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|----------------|-----------------|------|-----|----------------------------------|
| `compaction_interval` | int | 选填 | 0 (禁用) | 对话轮次间隔触发压缩（按用户消息数计数，类似 ADK 的 compaction_interval） |
| `overlap_size` | int | 选填 | 1 | 压缩窗口间保留的重叠消息数（类似 ADK 的 overlap_size） |
| `token_threshold` | int | 选填 | 0 (禁用) | Token 数量阈值触发压缩 |
| `compaction_summary_template` | string | 选填 | 见下方 | 摘要消息模板，使用 `{summary}` 占位符 |

默认摘要模板：
```
[Context Summary] The following is a summary of the previous conversation:
{summary}
```

### 作用域状态管理配置

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|----------------|-----------------|------|-----|----------------------------------|
| `state_scope` | string | 选填 | "session" | 状态作用域前缀：session/user/app/temp |
| `state_header_prefix` | string | 选填 | "x-context-state" | 状态相关请求头前缀 |

## 配置示例

### 基础上下文限制

```yaml
max_messages: 10
preserve_system_message: true
preserve_last_n: 2
summarize_strategy: sliding_window
```

### Token 限制

```yaml
max_tokens: 4000
preserve_system_message: true
preserve_last_n: 1
token_estimate_ratio: 4.0
```

### 上下文压缩（推荐，参考 Google ADK）

```yaml
summarize_strategy: compaction
compaction_interval: 3
overlap_size: 2
preserve_system_message: true
preserve_last_n: 2
compaction_summary_template: "[上下文摘要] 以下是之前对话的摘要：\n{summary}"
```

### Token 阈值触发压缩

```yaml
summarize_strategy: compaction
token_threshold: 2000
overlap_size: 2
preserve_system_message: true
token_estimate_ratio: 4.0
```

### 启用记忆注入

```yaml
max_messages: 20
inject_memory: true
memory_key: "x-session-memory"
preserve_system_message: true
```

### 作用域状态管理

```yaml
state_scope: "user"
state_header_prefix: "x-context-state"
inject_memory: true
memory_key: "x-session-memory"
```

## 工作原理

### 滑动窗口策略（sliding_window）

从最新消息开始保留，直到达到限制：

```
原始消息: [系统提示, 用户1, 助手1, 用户2, 助手2, 用户3, 助手3, 用户4]
max_messages: 4

处理后: [系统提示, 助手2, 用户3, 助手3, 用户4]
```

### 截断策略（truncate）

直接截断超出限制的早期消息：

```
原始消息: [系统提示, 用户1, 助手1, 用户2, 助手2, 用户3]
max_messages: 3

处理后: [系统提示, 助手2, 用户3]
```

### 上下文压缩策略（compaction）— 参考 Google ADK

将较早的消息压缩为摘要消息，同时保留最近的消息以维持上下文连续性。类似于 Google ADK 的 `EventsCompactionConfig`：

```
原始消息: [系统提示, 用户1, 助手1, 用户2, 助手2, 用户3, 助手3, 用户4]
compaction_interval: 3, overlap_size: 2

处理后: [系统提示, [压缩摘要: 用户1+助手1+用户2+助手2], 助手3, 用户4]
```

**压缩触发条件（满足任一即触发）：**
1. `compaction_interval`: 对话轮次达到设定值
2. `token_threshold`: 总 Token 数超过阈值
3. `max_messages`: 消息数超过上限
4. `max_tokens`: Token 数超过上限

**重叠窗口（overlap_size）：**
类似 Google ADK 的 overlap_size，在压缩边界处保留消息，确保上下文不会在摘要边界处断裂。

### 记忆注入

当启用记忆注入时，插件会从请求头中读取会话记忆并注入到上下文中：

```
请求头: x-session-memory: [{"role":"assistant","content":"之前讨论了天气"}]

原始消息: [系统提示, 用户: "今天呢?"]

处理后: [系统提示, 助手: "之前讨论了天气", 用户: "今天呢?"]
```

### 作用域状态管理

参考 Google ADK 的 State 管理系统，支持四种作用域前缀：
- **session**: 仅在当前会话中有效（默认）
- **user**: 跨会话持久化，与用户关联
- **app**: 全局共享，应用级别
- **temp**: 仅在当前请求有效，不持久化

状态通过请求头传递：`{state_header_prefix}-{scope}`

## 请求示例

### 基础使用

```bash
curl http://localhost/v1/chat/completions \
-H "content-type: application/json" \
-d '{
  "model": "gpt-3.5-turbo",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant"},
    {"role": "user", "content": "Message 1"},
    {"role": "assistant", "content": "Response 1"},
    {"role": "user", "content": "Message 2"},
    {"role": "assistant", "content": "Response 2"},
    {"role": "user", "content": "Message 3"},
    {"role": "assistant", "content": "Response 3"},
    {"role": "user", "content": "Current question"}
  ]
}'
```

### 使用压缩策略

配置 `summarize_strategy: compaction, compaction_interval: 3, overlap_size: 2` 后，处理后发送到后端的请求将包含：

```json
{
  "messages": [
    {"role": "system", "content": "You are a helpful assistant"},
    {"role": "system", "content": "[Context Summary] The following is a summary of the previous conversation:\nuser: Message 1\nassistant: Response 1\nuser: Message 2\nassistant: Response 2"},
    {"role": "assistant", "content": "Response 3"},
    {"role": "user", "content": "Current question"}
  ]
}
```

## 使用场景

1. **控制 API 成本**：限制发送给模型的上下文长度以减少 Token 消耗
2. **避免上下文溢出**：确保请求不超过模型的上下文窗口限制
3. **会话管理**：在无状态的 API 调用中维护对话记忆
4. **性能优化**：减少处理时间和响应延迟
5. **长对话支持**：通过上下文压缩支持超长对话而不丢失关键信息
6. **多作用域状态管理**：按 session/user/app/temp 管理不同生命周期的状态

## 注意事项

1. Token 估算是近似值，实际 Token 数可能有所不同
2. 系统提示词默认被保护，不会被截断
3. `preserve_last_n` 确保最近的消息不会被截断
4. 记忆注入需要配合会话管理服务使用
5. 上下文压缩使用提取式摘要（非 LLM 生成），适合网关层快速处理
6. 建议 `overlap_size` 设置为 1-3，以平衡上下文连续性和压缩效率
