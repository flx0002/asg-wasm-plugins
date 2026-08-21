package main

import (
	"ai-agent-guard/config"
	"sync"
	"time"

	"github.com/higress-group/wasm-go/pkg/log"
)

// 熔断器状态
const (
	CircuitClosed   = "closed"
	CircuitOpen     = "open"
	CircuitHalfOpen = "half_open"
)

// CircuitBreakerState 熔断器状态（每个 VM 独立维护）
type CircuitBreakerState struct {
	mu               sync.Mutex
	redisState       string
	redisFailures    int
	redisLastFailure int64 // Unix 时间戳（秒）
	redisHalfOpenUsed int   // 半开状态已使用的探测次数

	policyState       string
	policyFailures    int
	policyLastFailure int64
	policyHalfOpenUsed int
}

// globalCircuitBreaker 全局熔断器状态（每个 Wasm VM 独立）
var globalCircuitBreaker = &CircuitBreakerState{
	redisState:  CircuitClosed,
	policyState: CircuitClosed,
}

// AllowRedisRequest 检查 Redis 熔断器是否允许请求
func (cb *CircuitBreakerState) AllowRedisRequest(cfg *config.AgentGuardConfig) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now().Unix()

	switch cb.redisState {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// 检查是否已过恢复超时时间
		if now-cb.redisLastFailure >= int64(cfg.CircuitBreaker.Redis.RecoveryTimeout) {
			cb.redisState = CircuitHalfOpen
			cb.redisHalfOpenUsed = 0
			log.Info("redis circuit breaker: open -> half_open")
			return true
		}
		return false
	case CircuitHalfOpen:
		// 半开状态下限制并发探测
		if cb.redisHalfOpenUsed < cfg.CircuitBreaker.Redis.HalfOpenMaxCalls {
			cb.redisHalfOpenUsed++
			return true
		}
		return false
	}
	return true
}

// RecordRedisSuccess 记录 Redis 调用成功
func (cb *CircuitBreakerState) RecordRedisSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.redisState == CircuitHalfOpen {
		// 半开状态成功 → 关闭熔断器
		cb.redisState = CircuitClosed
		cb.redisFailures = 0
		log.Info("redis circuit breaker: half_open -> closed")
	} else if cb.redisState == CircuitClosed {
		// 关闭状态成功 → 重置失败计数
		cb.redisFailures = 0
	}
}

// RecordRedisFailure 记录 Redis 调用失败
func (cb *CircuitBreakerState) RecordRedisFailure(cfg *config.AgentGuardConfig) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now().Unix()
	cb.redisLastFailure = now
	cb.redisFailures++

	switch cb.redisState {
	case CircuitClosed:
		if cb.redisFailures >= cfg.CircuitBreaker.Redis.FailureThreshold {
			cb.redisState = CircuitOpen
			log.Warnf("redis circuit breaker: closed -> open (failures=%d)", cb.redisFailures)
		}
	case CircuitHalfOpen:
		// 半开状态失败 → 重新打开熔断器
		cb.redisState = CircuitOpen
		log.Warn("redis circuit breaker: half_open -> open")
	}
}

// GetRedisState 获取 Redis 熔断器状态
func (cb *CircuitBreakerState) GetRedisState() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.redisState
}
