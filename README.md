---
title: AI 上下文管理
keywords: [ AI网关, 上下文管理, 记忆管理 ]
description: AI 上下文管理和记忆管理插件配置参考
---

## 功能说明

AI 上下文管理插件，用于管理 LLM 对话的上下文窗口，支持：
- 消息数量限制
- Token 数量估算和限制
- 系统提示词保护
- 滑动窗口策略
- 会话记忆注入

## 运行属性

插件执行阶段：`默认阶段`
插件执行优先级：`500`

## 配置说明

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|----------------|-----------------|------|-----|----------------------------------|
| `max_messages` | int | 选填 | 0 (无限制) | 上下文最大消息数量 |
| `max_tokens` | int | 选填 | 0 (无限制) | 上下文最大 Token 数量（估算） |
| `preserve_system_message` | bool | 选填 | true | 是否保留系统提示词 |
| `preserve_last_n` | int | 选填 | 2 | 强制保留最近 N 条消息 |
| `summarize_strategy` | string | 选填 | "sliding_window" | 截断策略，可选 "truncate" 或 "sliding_window" |
| `token_estimate_ratio` | float | 选填 | 4.0 | Token 估算比率（字符数/Token） |
| `memory_key` | string | 选填 | "x-session-memory" | 会话记忆的请求头键名 |
| `inject_memory` | bool | 选填 | false | 是否注入会话记忆 |

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

### 启用记忆注入

```yaml
max_messages: 20
inject_memory: true
memory_key: "x-session-memory"
preserve_system_message: true
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

### 记忆注入

当启用记忆注入时，插件会从请求头中读取会话记忆并注入到上下文中：

```
请求头: x-session-memory: [{"role":"assistant","content":"之前讨论了天气"}]

原始消息: [系统提示, 用户: "今天呢?"]

处理后: [系统提示, 助手: "之前讨论了天气", 用户: "今天呢?"]
```

## 请求示例

使用基础配置发起请求：

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

如果配置 `max_messages: 4`，处理后发送到后端的请求将只包含：

```json
{
  "messages": [
    {"role": "system", "content": "You are a helpful assistant"},
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

## 注意事项

1. Token 估算是近似值，实际 Token 数可能有所不同
2. 系统提示词默认被保护，不会被截断
3. `preserve_last_n` 确保最近的消息不会被截断
4. 记忆注入需要配合会话管理服务使用
