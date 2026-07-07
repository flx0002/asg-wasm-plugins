package main

// luaUpdateSessionMeta 原子更新 Session 风险评分和统计信息
//
// KEYS[1] = Session meta Hash key
// ARGV[1] = 当前时间戳（秒）
// ARGV[2] = 衰减时间常数 τ（秒）
// ARGV[3] = 风险增量
// ARGV[4] = Token 增量
// ARGV[5] = Session 超时时间（秒）
//
// 返回值：更新后的风险评分
const luaUpdateSessionMeta = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local tau = tonumber(ARGV[2])
local risk_delta = tonumber(ARGV[3])
local token_delta = tonumber(ARGV[4])
local session_timeout = tonumber(ARGV[5])

-- 读取当前状态
local old_risk = tonumber(redis.call('HGET', key, 'risk_score') or '0')
local last_active = tonumber(redis.call('HGET', key, 'last_active_time') or ARGV[1])
local request_count = tonumber(redis.call('HGET', key, 'request_count') or '0')
local step_count = tonumber(redis.call('HGET', key, 'step_count') or '0')
local token_count = tonumber(redis.call('HGET', key, 'token_count') or '0')
local violation_count = tonumber(redis.call('HGET', key, 'violation_count') or '0')
local created_at = tonumber(redis.call('HGET', key, 'created_at') or '0')

-- 计算时间衰减
local delta_t = now - last_active
if delta_t < 0 then
    delta_t = 0
end
local decay_factor = math.exp(-delta_t / tau)

-- 计算新风险评分：max(历史评分 × 衰减系数 + 增量, 增量)
local new_risk = old_risk * decay_factor + risk_delta
if risk_delta > new_risk then
    new_risk = risk_delta
end
if new_risk > 100 then
    new_risk = 100
end

-- 如果有违规事件，增加违规计数
if risk_delta > 0 then
    violation_count = violation_count + 1
end

-- 更新所有字段
if created_at == 0 then
    created_at = now
end
redis.call('HMSET', key,
    'risk_score', tostring(new_risk),
    'request_count', tostring(request_count + 1),
    'step_count', tostring(step_count + 1),
    'token_count', tostring(token_count + token_delta),
    'violation_count', tostring(violation_count),
    'last_active_time', tostring(now),
    'created_at', tostring(created_at)
)

-- 设置/刷新过期时间
redis.call('EXPIRE', key, session_timeout)

return tostring(math.floor(new_risk))
`

// luaCheckRateLimit 滑动窗口限流检查
//
// KEYS[1] = 请求计数窗口 key
// ARGV[1] = 窗口大小（秒）
// ARGV[2] = 最大请求数
//
// 返回值：{当前计数, 是否允许(1/0)}
const luaCheckRateLimit = `
local key = KEYS[1]
local window = tonumber(ARGV[1])
local max_requests = tonumber(ARGV[2])

local current = tonumber(redis.call('GET', key) or '0')
if current >= max_requests then
    return {current, 0}
end

current = redis.call('INCR', key)
if current == 1 then
    redis.call('EXPIRE', key, window)
end

return {current, 1}
`

// luaAppendAuditLog 原子写入审计日志详情和索引
//
// KEYS[1] = ZSET key（agent_audit:{sessionId}）
// KEYS[2] = 日志详情 key（agent_audit_log:{eventId}）
// KEYS[3] = 用户维度索引 key（agent_audit:user:{userId} 或 agent_audit:user:untrusted_anonymous；空串=跳过）
// KEYS[4] = 智能体维度索引 key（agent_audit:agent:{agentId}；空串=跳过）
// KEYS[5] = 调用者滑动窗口 key（agent_behavior:callers:{agentId}；空串=跳过）
// ARGV[1] = 事件 ID
// ARGV[2] = 日志 JSON 数据
// ARGV[3] = Score（毫秒时间戳 × 1000 + 序列号）
// ARGV[4] = 兜底 TTL（秒）——用于 Session/Agent 索引
// ARGV[5] = userId（调用者窗口 member）
// ARGV[6] = nowMs（调用者窗口 score）
// ARGV[7] = callersTtl（调用者窗口 TTL，秒）
// ARGV[8] = untrustedFlag（"1"=未信任聚合桶，应用限容+短 TTL；"0"=正常）
// ARGV[9] = untrustedTtl（未信任桶 TTL，秒）
//
// 返回值：'-1' 表示详情写入失败，其他表示 Session ZSET 当前条数
const luaAppendAuditLog = `
local zsetKey = KEYS[1]
local logKey = KEYS[2]
local userKey = KEYS[3]
local agentKey = KEYS[4]
local callersKey = KEYS[5]

local eventId = ARGV[1]
local data = ARGV[2]
local score = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local userId = ARGV[5]
local nowMs = tonumber(ARGV[6])
local callersTtl = tonumber(ARGV[7])
local untrustedFlag = ARGV[8]
local untrustedTtl = tonumber(ARGV[9])

-- 1. 先写入完整日志详情（pcall 容错）
-- 注意：Redis Lua 中 pcall 失败时返回带 .err 属性的 table，而非 false/nil
-- 因此必须检查 res.err，不能用 if not res then 判断
local res2 = redis.pcall('SET', logKey, data, 'EX', ttl)
if res2.err then
    -- 详情写入失败（如 Redis 内存满），直接返回，不写索引，避免脏索引
    return '-1'
end

-- 2. 详情写入成功，才写 Session ZSET 索引
local res1 = redis.pcall('ZADD', zsetKey, score, eventId)
if not res1.err then
    redis.pcall('EXPIRE', zsetKey, ttl)
end

-- 3. 写用户维度索引（方案 3.3.6）
if userKey ~= '' then
    redis.pcall('ZADD', userKey, score, eventId)
    if untrustedFlag == '1' then
        -- 未信任聚合桶：短 TTL + 限容 10000（防 Key 爆炸）
        redis.pcall('EXPIRE', userKey, untrustedTtl)
        local lenRes = redis.pcall('ZCARD', userKey)
        if not lenRes.err then
            local len = tonumber(lenRes) or 0
            if len > 10000 then
                -- ZSET 按 score 升序，排名 0~(len-10001) 为最旧数据
                redis.pcall('ZREMRANGEBYRANK', userKey, 0, len - 10001)
            end
        end
    else
        -- 信任用户索引：与 Session 索引对齐 TTL
        redis.pcall('EXPIRE', userKey, ttl)
    end
end

-- 4. 写智能体维度索引（方案 3.3.6）
if agentKey ~= '' then
    redis.pcall('ZADD', agentKey, score, eventId)
    redis.pcall('EXPIRE', agentKey, ttl)
end

-- 5. 维护智能体调用者滑动窗口（方案 3.3.8：横向移动检测用）
if callersKey ~= '' and userId ~= '' then
    redis.pcall('ZADD', callersKey, nowMs, userId)
    -- 清理 5 分钟前数据（300000ms）
    redis.pcall('ZREMRANGEBYSCORE', callersKey, 0, nowMs - 300000)
    redis.pcall('EXPIRE', callersKey, callersTtl)
end

local res3 = redis.pcall('ZCARD', zsetKey)
if res3.err then
    return '1'
end
return tostring(res3)
`
