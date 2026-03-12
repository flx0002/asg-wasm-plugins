---
title: AI Token 计量和配额管理
keywords: [ AI网关, Token计量, 配额管理 ]
description: AI Token 精准计量和配额管理插件配置参考
---

## 功能说明

AI Token 计量和配额管理插件，用于：
- 精准记录每个消费者的 Token 使用量
- 支持输入/输出 Token 分别计量
- 支持 Token 配额管理和限制
- 支持按权重计费（不同 Token 类型不同价格）
- 使用 Redis 存储计量数据

## 运行属性

插件执行阶段：`默认阶段`
插件执行优先级：`100`

## 配置说明

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|----------------|-----------------|------|-----|----------------------------------|
| `redis` | object | 选填 | - | Redis 连接配置 |
| `redis_key_prefix` | string | 选填 | "ai_token_billing:" | Redis 键前缀 |
| `consumer_header` | string | 选填 | "x-mse-consumer" | 消费者标识请求头 |
| `quota_enforcement` | bool | 选填 | false | 是否启用配额限制 |
| `deny_message` | string | 选填 | "Token quota exceeded" | 超出配额时的错误消息 |
| `input_token_multiplier` | float | 选填 | 1.0 | 输入 Token 计费权重 |
| `output_token_multiplier` | float | 选填 | 1.0 | 输出 Token 计费权重 |
| `log_usage` | bool | 选填 | true | 是否记录使用日志 |

redis 对象配置说明：

| 名称 | 数据类型 | 填写要求 | 默认值 | 描述 |
|----------------|-----------------|------|-----|----------------------------------|
| `service_name` | string | 必填 | - | Redis 服务名 |
| `service_port` | int | 选填 | 6379 | Redis 服务端口 |
| `username` | string | 选填 | - | Redis 用户名 |
| `password` | string | 选填 | - | Redis 密码 |
| `timeout` | int | 选填 | 1000 | 连接超时（毫秒） |
| `database` | int | 选填 | 0 | Redis 数据库索引 |

## 配置示例

### 基础计量配置

```yaml
redis:
  service_name: redis-service.dns
  service_port: 6379
  password: "your_password"
redis_key_prefix: "ai_billing:"
consumer_header: "x-api-key"
log_usage: true
```

### 启用配额限制

```yaml
redis:
  service_name: redis-service.dns
  service_port: 6379
  password: "your_password"
redis_key_prefix: "ai_billing:"
consumer_header: "x-mse-consumer"
quota_enforcement: true
deny_message: "您的 Token 配额已用完，请联系管理员"
```

### 差异化计费

```yaml
redis:
  service_name: redis-service.dns
  service_port: 6379
redis_key_prefix: "ai_billing:"
input_token_multiplier: 1.0
output_token_multiplier: 3.0  # 输出 Token 3倍计费
log_usage: true
```

## Redis 数据结构

插件在 Redis 中存储以下键：

| 键格式 | 描述 |
|--------|------|
| `{prefix}usage:{consumer}` | 总 Token 使用量（加权） |
| `{prefix}input:{consumer}` | 输入 Token 使用量 |
| `{prefix}output:{consumer}` | 输出 Token 使用量 |
| `{prefix}quota:{consumer}` | 剩余配额 |

## 配额管理

### 设置配额

通过 Redis 命令直接设置：

```bash
redis-cli SET ai_billing:quota:user123 100000
```

### 查询使用量

```bash
redis-cli GET ai_billing:usage:user123
redis-cli GET ai_billing:input:user123
redis-cli GET ai_billing:output:user123
```

## 请求示例

正常请求：

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

响应后，Redis 中将记录：
- `ai_billing:input:user123`: 输入 Token 数
- `ai_billing:output:user123`: 输出 Token 数
- `ai_billing:usage:user123`: 总使用量（加权）

### 超出配额响应

当配额耗尽且 `quota_enforcement: true` 时：

```json
{
  "error": {
    "message": "Token quota exceeded",
    "type": "quota_exceeded",
    "code": "insufficient_quota"
  }
}
```

## 使用场景

1. **按用量计费**：精确记录每个用户的 Token 使用量用于计费
2. **配额管理**：限制用户的 Token 使用量，防止超额使用
3. **成本控制**：监控和控制 AI API 调用成本
4. **差异化定价**：对输入和输出 Token 采用不同的计费策略

## 注意事项

1. 需要配置 Redis 服务才能持久化存储使用数据
2. Token 使用量从 LLM 响应中提取，需要后端服务返回 usage 字段
3. 配额检查在请求开始时进行，不会阻止已经开始的请求
4. 建议在生产环境中启用 Redis 持久化
