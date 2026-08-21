package main

import (
	"ai-agent-guard/config"
	"fmt"
	"sync"
	"time"

	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/tidwall/resp"
)

// ===== 黑名单 Redis Key 格式（方案 3.3.7）=====
const (
	RedisKeyBlacklistUser  = "agent_behavior:blacklist:user:%s"
	RedisKeyBlacklistAgent = "agent_behavior:blacklist:agent:%s"
)

// blacklistCacheTTL 本地缓存 TTL（秒）—— 方案 3.3.7：1s 缓存
const blacklistCacheTTL = 1

// blacklistHighRiskThreshold 高危 Session 风险分阈值，触发实时黑名单检查
const blacklistHighRiskThreshold = 50

// blacklistCacheEntry 本地缓存条目
type blacklistCacheEntry struct {
	blacklisted bool
	fetchTime   int64
}

// globalBlacklistCache VM 级黑名单缓存（每个 Wasm VM 独立）
var globalBlacklistCache = struct {
	sync.RWMutex
	entries map[string]blacklistCacheEntry
}{
	entries: make(map[string]blacklistCacheEntry),
}

// blacklistKeys 根据 UserID/AgentID 生成黑名单 Redis Key
// 未信任用户（untrusted_anonymous）不查用户黑名单，仅查 Agent 黑名单
func blacklistKeys(rs *RequestState) []string {
	keys := []string{}
	if rs.UserID != "" && rs.UserID != UntrustedUserID {
		keys = append(keys, fmt.Sprintf(RedisKeyBlacklistUser, rs.UserID))
	}
	if rs.AgentID != "" {
		keys = append(keys, fmt.Sprintf(RedisKeyBlacklistAgent, rs.AgentID))
	}
	return keys
}

// getCachedBlacklist 从本地缓存读取黑名单状态（1s TTL）
// 返回 (hit, blacklisted)：hit=false 表示有 Key 缓存未命中需查 Redis
func getCachedBlacklist(keys []string) (hit bool, blacklisted bool) {
	now := time.Now().Unix()
	globalBlacklistCache.RLock()
	defer globalBlacklistCache.RUnlock()
	for _, k := range keys {
		entry, ok := globalBlacklistCache.entries[k]
		if !ok || now-entry.fetchTime > blacklistCacheTTL {
			return false, false
		}
		if entry.blacklisted {
			return true, true
		}
	}
	return true, false
}

// setBlacklistCache 写入本地缓存
func setBlacklistCache(key string, blacklisted bool) {
	globalBlacklistCache.Lock()
	defer globalBlacklistCache.Unlock()
	globalBlacklistCache.entries[key] = blacklistCacheEntry{
		blacklisted: blacklisted,
		fetchTime:   time.Now().Unix(),
	}
}

// checkBlacklist 黑名单检查入口（方案 3.3.7）
//
// 策略：
//  1. 先查本地缓存（1s TTL），命中则同步回调
//  2. 缓存未命中则异步 MGet Redis，回调在 Redis 返回后触发
//
// callback 保证被调用且仅调用一次。
// blocked=true 表示命中黑名单应拦截，reason 为拦截原因。
func checkBlacklist(cfg *config.AgentGuardConfig, rs *RequestState, callback func(blocked bool, reason string)) {
	keys := blacklistKeys(rs)
	if len(keys) == 0 {
		callback(false, "")
		return
	}

	// 1. 先查本地缓存
	if hit, blacklisted := getCachedBlacklist(keys); hit {
		if blacklisted {
			callback(true, "blacklist hit (cached)")
		} else {
			callback(false, "")
		}
		return
	}

	// 2. 缓存未命中，异步 MGet Redis
	if !cfg.RedisClient.Ready() || !globalCircuitBreaker.AllowRedisRequest(cfg) {
		// Redis 不可用，放行（黑名单检查不阻断正常流量）
		callback(false, "")
		return
	}

	if err := cfg.RedisClient.MGet(keys, func(response resp.Value) {
		handleBlacklistResponse(keys, response, callback)
	}); err != nil {
		log.Warnf("blacklist mget failed: %v", err)
		callback(false, "")
	}
}

// checkBlacklistRealtime 高危 Session 实时黑名单检查（绕过缓存）
//
// 方案 3.3.7：高危 Session（SessionMeta.RiskScore >= 50 或 BehaviorRiskScore > 80）
// 绕过本地缓存，实时 GET Redis，最小化逃逸窗口。
func checkBlacklistRealtime(cfg *config.AgentGuardConfig, rs *RequestState, callback func(blocked bool, reason string)) {
	keys := blacklistKeys(rs)
	if len(keys) == 0 {
		callback(false, "")
		return
	}
	if !cfg.RedisClient.Ready() || !globalCircuitBreaker.AllowRedisRequest(cfg) {
		callback(false, "")
		return
	}

	if err := cfg.RedisClient.MGet(keys, func(response resp.Value) {
		handleBlacklistResponse(keys, response, callback)
	}); err != nil {
		log.Warnf("blacklist realtime mget failed: %v", err)
		callback(false, "")
	}
}

// handleBlacklistResponse 处理 MGet 返回，更新缓存并回调
func handleBlacklistResponse(keys []string, response resp.Value, callback func(blocked bool, reason string)) {
	arr := response.Array()
	blocked := false
	for i, v := range arr {
		if i >= len(keys) {
			break
		}
		if !v.IsNull() && v.String() != "" {
			setBlacklistCache(keys[i], true)
			blocked = true
		} else {
			setBlacklistCache(keys[i], false)
		}
	}
	if blocked {
		callback(true, "blacklist hit (redis)")
	} else {
		callback(false, "")
	}
}

// isHighRiskSession 判断是否为高危 Session（触发实时黑名单检查）
// 方案 3.3.7：SessionMeta.RiskScore >= 50 或 BehaviorRiskScore > 80
func isHighRiskSession(rs *RequestState) bool {
	if rs.SessionMeta != nil && rs.SessionMeta.RiskScore >= blacklistHighRiskThreshold {
		return true
	}
	if rs.BehaviorRiskScore > 80 {
		return true
	}
	return false
}
