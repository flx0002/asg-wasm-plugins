package main

import (
	"ai-agent-guard/config"
	"encoding/json"
	"fmt"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/resp"
)

const PromptGuardEventKey = "prompt_guard_event"

// collectSecurityEvents 只从 wasm.ai_log 一级 filter state 读取 ai-prompt-guard
// 写入的真实命中事件。两级路径 security_events 属于插件私有 VM，跨插件不可见；
// 任何从 HTTP 状态码反推事件的做法都会把其它插件的 403 误报成提示注入，已移除。
func collectSecurityEvents(rs *RequestState) []SecurityEvent {
	return collectEventsFromAILog()
}

// collectEventsFromAILog 解码 ai_log（marshalStr 产物是去掉外层引号的 JSON 字符串
// 字面量内容），取出 prompt_guard_event。该值由 ai-prompt-guard 以 JSON 字符串写入，
// 兼容直接以数组写入的历史形态。
func collectEventsFromAILog() []SecurityEvent {
	raw, err := proxywasm.GetProperty([]string{wrapper.AILogKey})
	if err != nil || len(raw) == 0 {
		return nil
	}
	var jsonStr string
	if err := json.Unmarshal([]byte(`"`+string(raw)+`"`), &jsonStr); err != nil {
		jsonStr = string(raw)
	}
	var attr map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &attr); err != nil {
		log.Warnf("collectEventsFromAILog: unmarshal ai_log failed: %v", err)
		return nil
	}
	v, ok := attr[PromptGuardEventKey]
	if !ok || len(v) == 0 {
		return nil
	}
	var encoded string
	if json.Unmarshal(v, &encoded) == nil {
		v = []byte(encoded)
	}
	var events []SecurityEvent
	if err := json.Unmarshal(v, &events); err != nil {
		log.Warnf("collectEventsFromAILog: unmarshal prompt_guard_event failed: %v", err)
		return nil
	}
	return events
}

// securityEventKey 供写审计前合并与 buildAuditEntry 输出共用。
// 必须带上命中原文与时间戳：同一请求里多条 message 命中同一规则时，
// 旧键会把它们折叠成一条，详情里就看不到各自的输入。
func securityEventKey(e SecurityEvent) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s", e.TimestampMs, e.Type, e.RuleName,
		e.MatchedText, e.Direction, e.HitContent, e.Detail)
}

// mergeSecurityEventsFromAILog 在写审计前统一增量合并一次，覆盖响应体阶段才产生的
// 命中（响应体晚于 onHttpResponseHeaders 的首次收集）。同一事件按
// timestamp_ms + rule_name + matched_text + direction 去重，避免重复计数。
// blocked 只取插件按 detectMode 明确传递的值，不再从 HTTP 状态码反推。
func mergeSecurityEventsFromAILog(rs *RequestState) {
	if rs == nil {
		return
	}
	keyOf := securityEventKey
	for _, e := range collectEventsFromAILog() {
		key := keyOf(e)
		dup := false
		for _, existing := range rs.Events {
			if keyOf(existing) == key {
				dup = true
				break
			}
		}
		if !dup {
			rs.Events = append(rs.Events, e)
		}
		if e.Blocked {
			rs.Blocked = true
		}
	}
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
