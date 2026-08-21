---
title: AI PII Detection and Protection
keywords: [ AI Gateway, PII Detection, Sensitive Information Protection ]
description: AI PII Detection and Protection Plugin Configuration Reference
---

## Function Description

The AI PII (Personally Identifiable Information) Detection and Protection plugin automatically identifies and redacts sensitive personal information in AI requests and responses, including but not limited to:
- Email addresses
- Phone numbers (China, International formats)
- ID card numbers
- Credit card numbers
- Social Security Numbers (SSN)
- IP addresses

## Execution Properties

Plugin execution phase: `Default Phase`
Plugin execution priority: `350`

## Configuration Description

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `rules` | array of rule | optional | Built-in default rules | List of PII detection rules |
| `protect_request` | bool | optional | true | Whether to protect PII in requests |
| `protect_response` | bool | optional | false | Whether to protect PII in responses |
| `log_matches` | bool | optional | true | Whether to log PII matches (without actual values) |

Rule object configuration:

| Name | Data Type | Requirement | Default Value | Description |
|----------------|-----------------|------|-----|----------------------------------|
| `name` | string | optional | - | Rule name for logging |
| `pattern` | string | required | - | Regex pattern to match PII |
| `replacement` | string | optional | "[REDACTED]" | String to replace matched content |

## Default Rules

The plugin includes the following default PII detection rules:

| Rule Name | Description | Replacement |
|----------|------|---------|
| email | Email addresses | [EMAIL_REDACTED] |
| phone_cn | China mobile phone | [PHONE_REDACTED] |
| phone_intl | International phone numbers | [PHONE_REDACTED] |
| id_card_cn | China ID card numbers | [ID_REDACTED] |
| credit_card | Credit card numbers | [CARD_REDACTED] |
| ssn_us | US Social Security Numbers | [SSN_REDACTED] |
| ipv4 | IPv4 addresses | [IP_REDACTED] |

## Configuration Example

### Using Default Rules

```yaml
protect_request: true
protect_response: true
log_matches: true
```

### Custom Rules

```yaml
rules:
  - name: email
    pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}"
    replacement: "[EMAIL]"
  - name: phone_cn
    pattern: "1[3-9]\\d{9}"
    replacement: "[PHONE_REDACTED]"
  - name: custom_id
    pattern: "ID-\\d{8}"
    replacement: "[INTERNAL_ID_REDACTED]"
protect_request: true
protect_response: false
```

## Request Example

Using the default configuration to make a request:

```bash
curl http://localhost/v1/chat/completions \
-H "content-type: application/json" \
-d '{
  "model": "gpt-3.5-turbo",
  "messages": [
    {
      "role": "user",
      "content": "My email is test@example.com and phone is 13812345678"
    }
  ]
}'
```

After processing by the plugin, the request sent to the backend will be:

```json
{
  "model": "gpt-3.5-turbo",
  "messages": [
    {
      "role": "user",
      "content": "My email is [EMAIL_REDACTED] and phone is [PHONE_REDACTED]"
    }
  ]
}
```

## Use Cases

1. **Compliance Requirements**: Ensure data sent to AI services does not contain sensitive personal information
2. **Data Security**: Prevent users from accidentally exposing personal information to AI models
3. **Privacy Protection**: Redact personal information that may appear in AI responses

## Notes

1. Regex patterns require proper escaping of special characters
2. Overly broad patterns may cause false positive redactions
3. Enabling response protection will add response processing latency
4. Consider disabling `log_matches` in production to avoid excessive logging
