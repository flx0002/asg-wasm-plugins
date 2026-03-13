---
title: AI Context Management
keywords: [ AI Gateway, Context Management, Memory Management, Context Compression ]
description: AI Context Management and Memory Management Plugin Configuration Reference
---

## Function Description

The AI Context Management plugin manages the context window for LLM conversations, inspired by Google ADK (Agent Development Kit) design, supporting:
- Message count limits
- Token count estimation and limits
- System prompt preservation
- Sliding window strategy
- **Context compression/compaction strategy** (inspired by Google ADK EventsCompactionConfig)
- **Compaction interval trigger** (trigger compression by conversation turns)
- **Token threshold trigger** (trigger compression by token count)
- **Overlap window** (preserve messages at compaction boundaries for context continuity)
- **Customizable summary template**
- **Turn-pair integrity** (keep user-assistant pairs as atomic units)
- **Instruction/message pinning** (pin messages by role to prevent eviction)
- **Tool message awareness** (handle tool_calls/tool_call_id/function_call/name)
- **Context caching hints** (inspired by ADK ContextCacheConfig)
- **Response token usage tracking** (extract token metadata from model responses)
- **Scoped state management** (session/user/app/temp prefixes, inspired by ADK State management)
- Session memory injection

## Execution Properties

Plugin execution phase: `Default Phase`
Plugin execution priority: `500`

## Configuration Description

### Basic Configuration

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `max_messages` | int | optional | 0 (unlimited) | Maximum number of messages in context |
| `max_tokens` | int | optional | 0 (unlimited) | Maximum token count (estimated) |
| `preserve_system_message` | bool | optional | true | Whether to preserve system prompt |
| `preserve_last_n` | int | optional | 2 | Force preserve last N messages |
| `summarize_strategy` | string | optional | "sliding_window" | Context management strategy: "truncate", "sliding_window", or "compaction" |
| `token_estimate_ratio` | float | optional | 4.0 | Token estimation ratio (characters/token) |
| `memory_key` | string | optional | "x-session-memory" | Request header key for session memory |
| `inject_memory` | bool | optional | false | Whether to inject session memory |

### Context Compression Configuration (Google ADK Style)

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `compaction_interval` | int | optional | 0 (disabled) | Conversation turn interval to trigger compaction, counted by user messages (similar to ADK's compaction_interval) |
| `overlap_size` | int | optional | 1 | Number of overlap messages to keep between compaction windows (similar to ADK's overlap_size) |
| `token_threshold` | int | optional | 0 (disabled) | Token count threshold to trigger compaction |
| `compaction_summary_template` | string | optional | see below | Summary message template, use `{summary}` placeholder |

Default summary template:
```
[Context Summary] The following is a summary of the previous conversation:
{summary}
```

### Scoped State Management Configuration

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `state_scope` | string | optional | "session" | State scope prefix: session/user/app/temp |
| `state_header_prefix` | string | optional | "x-context-state" | Prefix for state-related request headers |

### Turn-pair Integrity Configuration

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `preserve_turn_pairs` | bool | optional | false | Keep user-assistant message pairs as atomic units during context management |

### Instruction/Message Pinning Configuration

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `pinned_message_roles` | []string | optional | none | List of message roles to pin and never evict (e.g., ["tool", "function"]) |

### Context Caching Hints Configuration (Google ADK ContextCacheConfig Style)

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `cache_system_prompt` | bool | optional | false | Enable system prompt caching hints (adds response headers) |
| `cache_min_tokens` | int | optional | 0 | Minimum token count to trigger cache hints |

### Response Token Tracking Configuration

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `track_token_usage` | bool | optional | false | Extract token usage info from model responses and add to response headers |

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

### Context Compression (Recommended, Google ADK Style)

```yaml
summarize_strategy: compaction
compaction_interval: 3
overlap_size: 2
preserve_system_message: true
preserve_last_n: 2
compaction_summary_template: "[Context Summary] Previous conversation summary:\n{summary}"
```

### Token Threshold Compaction

```yaml
summarize_strategy: compaction
token_threshold: 2000
overlap_size: 2
preserve_system_message: true
token_estimate_ratio: 4.0
```

### Enable Memory Injection

```yaml
max_messages: 20
inject_memory: true
memory_key: "x-session-memory"
preserve_system_message: true
```

### Scoped State Management

```yaml
state_scope: "user"
state_header_prefix: "x-context-state"
inject_memory: true
memory_key: "x-session-memory"
```

### Turn-pair Integrity + Tool Message Pinning

```yaml
summarize_strategy: compaction
compaction_interval: 3
overlap_size: 2
preserve_turn_pairs: true
pinned_message_roles: ["tool", "function"]
preserve_system_message: true
```

### Context Caching Hints + Token Tracking

```yaml
cache_system_prompt: true
cache_min_tokens: 100
track_token_usage: true
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

### Compaction Strategy — Inspired by Google ADK

Compresses older messages into a summary message while keeping recent messages intact for context continuity. Similar to Google ADK's `EventsCompactionConfig`:

```
Original: [system, user1, assistant1, user2, assistant2, user3, assistant3, user4]
compaction_interval: 3, overlap_size: 2

Result: [system, [Compacted Summary: user1+assistant1+user2+assistant2], assistant3, user4]
```

**Compaction triggers (any one of these will trigger compaction):**
1. `compaction_interval`: Conversation turns reach the set value
2. `token_threshold`: Total token count exceeds threshold
3. `max_messages`: Message count exceeds limit
4. `max_tokens`: Token count exceeds limit

**Overlap window (overlap_size):**
Similar to Google ADK's overlap_size, preserves messages at the compaction boundary to ensure context continuity across summary boundaries.

### Memory Injection

When memory injection is enabled, the plugin reads session memory from request headers and injects it into the context:

```
Header: x-session-memory: [{"role":"assistant","content":"Previously discussed weather"}]

Original: [system, user: "What about today?"]

Result: [system, assistant: "Previously discussed weather", user: "What about today?"]
```

### Scoped State Management

Inspired by Google ADK's State management system, supports four scope prefixes:
- **session**: Valid only in the current session (default)
- **user**: Persists across sessions, associated with the user
- **app**: Global sharing, application level
- **temp**: Valid only for the current request, not persisted

State is passed through request headers: `{state_header_prefix}-{scope}`

### Turn-pair Integrity

When `preserve_turn_pairs: true` is enabled, context management checks message pair integrity after truncation/compaction:
- User-assistant message pairs are treated as atomic units
- Orphaned assistant messages (without corresponding user) are removed
- Trailing user messages (latest query) are preserved
- Tool/function/system messages are independently preserved

```
After truncation: [assistant2(orphaned), user3, assistant3, user4]
After turn-pair fix: [user3, assistant3, user4]
```

### Instruction/Message Pinning

When `pinned_message_roles: ["tool", "function"]` is configured, messages with pinned roles are never evicted during context management:

```
Original: [system, user1, assistant1, tool_result, user2, assistant2, user3]
max_messages: 3

Result: [system, tool_result(pinned), assistant2, user3]
```

### Context Caching Hints

When `cache_system_prompt: true` is enabled and system prompt tokens ≥ `cache_min_tokens`, caching hints are added to response headers:
- `x-context-cache-status: eligible` - Marks as cacheable
- `x-context-cache-tokens: <token_count>` - System prompt token count

### Response Token Tracking

When `track_token_usage: true` is enabled, token usage info is extracted from model responses:
- `x-context-prompt-tokens` - Input token count
- `x-context-completion-tokens` - Output token count
- `x-context-total-tokens` - Total token count

## Request Example

### Basic Usage

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

### Using Compaction Strategy

With `summarize_strategy: compaction, compaction_interval: 3, overlap_size: 2`, the request sent to the backend will include:

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

## Use Cases

1. **Control API Costs**: Limit context length sent to the model to reduce token consumption
2. **Avoid Context Overflow**: Ensure requests don't exceed the model's context window limit
3. **Session Management**: Maintain conversation memory in stateless API calls
4. **Performance Optimization**: Reduce processing time and response latency
5. **Long Conversation Support**: Support extended conversations through context compression without losing key information
6. **Multi-scope State Management**: Manage state with different lifecycles via session/user/app/temp scopes
7. **Tool Call Scenarios**: Properly handle complex conversations with tool_calls/function_call messages
8. **Token Cost Monitoring**: Monitor API call costs through response token tracking

## Notes

1. Token estimation is approximate; actual token counts may differ
2. System prompts are protected by default and won't be truncated
3. `preserve_last_n` ensures recent messages are not truncated
4. Memory injection requires a session management service
5. Context compression uses extractive summarization (not LLM-generated), suitable for fast gateway-layer processing
6. Recommended `overlap_size` of 1-3 to balance context continuity and compression efficiency
7. Enabling `preserve_turn_pairs` may result in slightly fewer messages than `max_messages`
8. Messages with `pinned_message_roles` are not counted towards `max_messages` limit
9. Context caching hints require upstream service support for actual caching implementation
