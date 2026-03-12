---
title: AI PII 检测和保护
keywords: [ AI网关, PII检测, 敏感信息保护 ]
description: AI PII 检测和保护插件配置参考
---

## 功能说明

AI PII（个人身份信息）检测和保护插件，用于在 AI 请求和响应中自动识别和脱敏敏感的个人信息，包括但不限于：
- 电子邮件地址
- 手机号码（中国、国际格式）
- 身份证号码
- 信用卡号码
- 社会安全号码（SSN）
- IP 地址

## 运行属性

插件执行阶段：`默认阶段`
插件执行优先级：`350`

## 配置说明

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|----------------|-----------------|------|-----|----------------------------------|
| `rules` | array of rule | 选填 | 内置默认规则 | PII 检测规则列表 |
| `protect_request` | bool | 选填 | true | 是否保护请求中的 PII |
| `protect_response` | bool | 选填 | false | 是否保护响应中的 PII |
| `log_matches` | bool | 选填 | true | 是否记录 PII 匹配（不记录实际值） |

rule 对象配置说明：

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|----------------|-----------------|------|-----|----------------------------------|
| `name` | string | 选填 | - | 规则名称，用于日志 |
| `pattern` | string | 必填 | - | 匹配 PII 的正则表达式 |
| `replacement` | string | 选填 | "[REDACTED]" | 替换匹配内容的字符串 |

## 默认规则

插件内置以下默认 PII 检测规则：

| 规则名称 | 描述 | 替换内容 |
|----------|------|---------|
| email | 电子邮件地址 | [EMAIL_REDACTED] |
| phone_cn | 中国手机号 | [PHONE_REDACTED] |
| phone_intl | 国际电话号码 | [PHONE_REDACTED] |
| id_card_cn | 中国身份证号 | [ID_REDACTED] |
| credit_card | 信用卡号 | [CARD_REDACTED] |
| ssn_us | 美国社会安全号 | [SSN_REDACTED] |
| ipv4 | IPv4 地址 | [IP_REDACTED] |

## 配置示例

### 使用默认规则

```yaml
protect_request: true
protect_response: true
log_matches: true
```

### 自定义规则

```yaml
rules:
  - name: email
    pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}"
    replacement: "[EMAIL]"
  - name: phone_cn
    pattern: "1[3-9]\\d{9}"
    replacement: "[手机号已脱敏]"
  - name: custom_id
    pattern: "ID-\\d{8}"
    replacement: "[内部ID已脱敏]"
protect_request: true
protect_response: false
```

## 请求示例

使用默认配置发起请求：

```bash
curl http://localhost/v1/chat/completions \
-H "content-type: application/json" \
-d '{
  "model": "gpt-3.5-turbo",
  "messages": [
    {
      "role": "user",
      "content": "我的邮箱是 test@example.com，手机是 13812345678"
    }
  ]
}'
```

经过插件处理后，发送到后端的请求为：

```json
{
  "model": "gpt-3.5-turbo",
  "messages": [
    {
      "role": "user",
      "content": "我的邮箱是 [EMAIL_REDACTED]，手机是 [PHONE_REDACTED]"
    }
  ]
}
```

## 使用场景

1. **合规要求**：确保发送给 AI 服务的数据不包含敏感个人信息
2. **数据安全**：防止用户无意中泄露个人信息给 AI 模型
3. **隐私保护**：在 AI 响应中脱敏可能出现的个人信息

## 注意事项

1. 正则表达式模式需要正确转义特殊字符
2. 过于宽泛的模式可能导致误脱敏
3. 启用响应保护会增加响应处理延迟
4. 建议在生产环境中关闭 `log_matches` 以避免日志过多
