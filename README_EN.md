---
title: AI Token Metering and Quota Management
keywords: [ AI Gateway, Token Metering, Quota Management ]
description: AI Token Precise Metering and Quota Management Plugin Configuration Reference
---

## Function Description

The AI Token Metering and Quota Management plugin provides:
- Precise recording of token usage per consumer
- Separate metering for input/output tokens
- Token quota management and enforcement
- Weighted billing (different pricing for different token types)
- Redis-based storage for metering data

## Execution Properties

Plugin execution phase: `Default Phase`
Plugin execution priority: `100`

## Configuration Description

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `redis` | object | optional | - | Redis connection configuration |
| `redis_key_prefix` | string | optional | "ai_token_billing:" | Redis key prefix |
| `consumer_header` | string | optional | "x-mse-consumer" | Consumer identifier header |
| `quota_enforcement` | bool | optional | false | Enable quota enforcement |
| `deny_message` | string | optional | "Token quota exceeded" | Error message when quota exceeded |
| `input_token_multiplier` | float | optional | 1.0 | Input token billing weight |
| `output_token_multiplier` | float | optional | 1.0 | Output token billing weight |
| `log_usage` | bool | optional | true | Enable usage logging |

Redis object configuration:

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `service_name` | string | required | - | Redis service name |
| `service_port` | int | optional | 6379 | Redis service port |
| `username` | string | optional | - | Redis username |
| `password` | string | optional | - | Redis password |
| `timeout` | int | optional | 1000 | Connection timeout (ms) |
| `database` | int | optional | 0 | Redis database index |

## Configuration Example

### Basic Metering Configuration

```yaml
redis:
  service_name: redis-service.dns
  service_port: 6379
  password: "your_password"
redis_key_prefix: "ai_billing:"
consumer_header: "x-api-key"
log_usage: true
```

### Enable Quota Enforcement

```yaml
redis:
  service_name: redis-service.dns
  service_port: 6379
  password: "your_password"
redis_key_prefix: "ai_billing:"
consumer_header: "x-mse-consumer"
quota_enforcement: true
deny_message: "Your token quota has been exhausted, please contact administrator"
```

### Differentiated Pricing

```yaml
redis:
  service_name: redis-service.dns
  service_port: 6379
redis_key_prefix: "ai_billing:"
input_token_multiplier: 1.0
output_token_multiplier: 3.0  # Output tokens charged at 3x rate
log_usage: true
```

## Redis Data Structure

The plugin stores the following keys in Redis:

| Key Format | Description |
|--------|------|
| `{prefix}usage:{consumer}` | Total token usage (weighted) |
| `{prefix}input:{consumer}` | Input token usage |
| `{prefix}output:{consumer}` | Output token usage |
| `{prefix}quota:{consumer}` | Remaining quota |

## Quota Management

### Setting Quota

Set directly via Redis command:

```bash
redis-cli SET ai_billing:quota:user123 100000
```

### Querying Usage

```bash
redis-cli GET ai_billing:usage:user123
redis-cli GET ai_billing:input:user123
redis-cli GET ai_billing:output:user123
```

## Request Example

Normal request:

```bash
curl http://localhost/v1/chat/completions \
-H "content-type: application/json" \
-H "x-mse-consumer: user123" \
-d '{
  "model": "gpt-3.5-turbo",
  "messages": [
    {"role": "user", "content": "Hello"}
  ]
}'
```

After the response, Redis will record:
- `ai_billing:input:user123`: Input token count
- `ai_billing:output:user123`: Output token count
- `ai_billing:usage:user123`: Total usage (weighted)

### Quota Exceeded Response

When quota is exhausted and `quota_enforcement: true`:

```json
{
  "error": {
    "message": "Token quota exceeded",
    "type": "quota_exceeded",
    "code": "insufficient_quota"
  }
}
```

## Use Cases

1. **Usage-based Billing**: Precisely record token usage per user for billing
2. **Quota Management**: Limit user token usage to prevent overuse
3. **Cost Control**: Monitor and control AI API call costs
4. **Differentiated Pricing**: Apply different billing strategies for input and output tokens

## Notes

1. Redis service configuration is required for persistent storage
2. Token usage is extracted from LLM response; backend must return usage field
3. Quota check occurs at request start and won't stop in-progress requests
4. Enable Redis persistence in production environments
