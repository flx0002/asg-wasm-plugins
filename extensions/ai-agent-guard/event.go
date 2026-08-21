package main

import (
	"ai-agent-guard/config"
	"encoding/json"
	"fmt"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/tidwall/resp"
)

// collectSecurityEvents 收集安全事件
// 首选方案：从 Dynamic Metadata 读取（零网络开销）
// 保底方案：从 Redis Event Key 读取
func collectSecurityEvents(rs *RequestState) []SecurityEvent {
	// 首选：Dynamic Metadata
	events := collectEventsFromMetadata()
	if len(events) > 0 {
		return events
	}

	// 保底：Redis 事件总线
	events = collectEventsFromRedis(rs)
	return events
}

// collectEventsFromMetadata 从 Dynamic Metadata 读取安全事件
func collectEventsFromMetadata() []SecurityEvent {
	data, err := proxywasm.GetProperty([]string{MetadataNamespaceSecurityEvt, "events"})
	if err != nil || len(data) == 0 {
		log.Warnf("collectEventsFromMetadata: no events in metadata, err=%v, data_len=%d", err, len(data))
		return nil
	}

	var events []SecurityEvent
	if err := json.Unmarshal(data, &events); err != nil {
		log.Warnf("unmarshal security events from metadata failed: %v", err)
		return nil
	}

	log.Debugf("collected %d security events from dynamic metadata", len(events))
	return events
}

// collectEventsFromRedis 从 Redis 事件总线读取安全事件（保底方案）
func collectEventsFromRedis(rs *RequestState) []SecurityEvent {
	// 此函数在响应头阶段调用，Redis 操作是异步的
	// 但在响应头阶段我们需要同步获取事件，因此这里使用空实现
	// 实际的 Redis 事件收集应在请求阶段通过异步方式预加载
	//
	// 注意：如果 Dynamic Metadata 方案不可用，安全插件会通过 Redis RPUSH 写入事件
	// ai-agent-guard 需要在请求阶段就发起异步 LRANGE 读取，并在响应阶段使用缓存结果
	//
	// 当前实现：如果 Dynamic Metadata 失败，返回空事件列表
	// 后续可通过在 RequestState 中缓存异步读取结果来优化
	return nil
}

// collectEventsFromRedisAsync 异步从 Redis 读取安全事件（在请求阶段调用）
// 读取结果缓存在 RequestState 中，供响应阶段使用
func collectEventsFromRedisAsync(cfg *config.AgentGuardConfig, rs *RequestState, callback func()) {
	key := fmt.Sprintf(RedisKeyEvent, rs.EventKey)

	err := cfg.RedisClient.LRange(key, 0, -1, func(response resp.Value) {
		arr := response.Array()
		for _, item := range arr {
			var event SecurityEvent
			if err := json.Unmarshal([]byte(item.String()), &event); err != nil {
				log.Warnf("unmarshal security event from redis failed: %v", err)
				continue
			}
			rs.Events = append(rs.Events, event)
		}

		// 读取完成后删除事件 key
		_ = cfg.RedisClient.Del(key, func(delResp resp.Value) {})

		if callback != nil {
			callback()
		}
	})

	if err != nil {
		log.Warnf("async read security events from redis failed: %v", err)
		if callback != nil {
			callback()
		}
	}
}
