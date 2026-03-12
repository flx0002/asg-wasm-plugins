---
title: AI Context Management
keywords: [ AI Gateway, Context Management, Memory Management ]
description: AI Context Management and Memory Management Plugin Configuration Reference
---

## Function Description

The AI Context Management plugin manages the context window for LLM conversations, supporting:
- Message count limits
- Token count estimation and limits
- System prompt preservation
- Sliding window strategy
- Session memory injection

## Execution Properties

Plugin execution phase: `Default Phase`
Plugin execution priority: `500`

## Configuration Description

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `max_messages` | int | optional | 0 (unlimited) | Maximum number of messages in context |
| `max_tokens` | int | optional | 0 (unlimited) | Maximum token count (estimated) |
| `preserve_system_message` | bool | optional | true | Whether to preserve system prompt |
| `preserve_last_n` | int | optional | 2 | Force preserve last N messages |
| `summarize_strategy` | string | optional | "sliding_window" | Truncation strategy: "truncate" or "sliding_window" |
| `token_estimate_ratio` | float | optional | 4.0 | Token estimation ratio (characters/token) |
| `memory_key` | string | optional | "x-session-memory" | Request header key for session memory |
| `inject_memory` | bool | optional | false | Whether to inject session memory |

## Configuration Example

### Basic Context Limit

```yaml
max_messages: 10
preserve_system_message: true
preserve_last_n: 2
summarize_strategy: sliding_window
```

### Token Limit

```yaml
max_tokens: 4000
preserve_system_message: true
preserve_last_n: 1
token_estimate_ratio: 4.0
```

### Enable Memory Injection

```yaml
max_messages: 20
inject_memory: true
memory_key: "x-session-memory"
preserve_system_message: true
```

## How It Works

### Sliding Window Strategy

Keeps messages starting from the most recent until the limit is reached:

```
Original: [system, user1, assistant1, user2, assistant2, user3, assistant3, user4]
max_messages: 4

Result: [system, assistant2, user3, assistant3, user4]
```

### Truncate Strategy

Directly truncates earlier messages that exceed the limit:

```
Original: [system, user1, assistant1, user2, assistant2, user3]
max_messages: 3

Result: [system, assistant2, user3]
```

### Memory Injection

When memory injection is enabled, the plugin reads session memory from request headers and injects it into the context:

```
Header: x-session-memory: [{"role":"assistant","content":"Previously discussed weather"}]

Original: [system, user: "What about today?"]

Result: [system, assistant: "Previously discussed weather", user: "What about today?"]
```

## Request Example

Using basic configuration to make a request:

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

With `max_messages: 4`, the request sent to the backend will only include:

```json
{
  "messages": [
    {"role": "system", "content": "You are a helpful assistant"},
    {"role": "assistant", "content": "Response 3"},
    {"role": "user", "content": "Current question"}
  ]
}
```

## Use Cases

1. **Control API Costs**: Limit context length sent to the model to reduce token consumption
2. **Avoid Context Overflow**: Ensure requests don't exceed the model's context window limit
3. **Session Management**: Maintain conversation memory in stateless API calls
4. **Performance Optimization**: Reduce processing time and response latency

## Notes

1. Token estimation is approximate; actual token counts may differ
2. System prompts are protected by default and won't be truncated
3. `preserve_last_n` ensures recent messages are not truncated
4. Memory injection requires a session management service
