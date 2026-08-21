// Copyright (c) 2024 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"ai-agent-guard/config"
	"fmt"
	"strconv"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/resp"
)

const pluginName = "ai-agent-guard"

// ===== 上行 Header（Client → Gateway）=====
const (
	HeaderSessionID      = "x-agent-session-id"
	HeaderStepIndex      = "x-agent-step-index"
	HeaderStepType       = "x-agent-step-type"
	HeaderToolName       = "x-agent-tool-name"
	HeaderToolParamsHash = "x-agent-tool-params-hash"
	HeaderParentStep     = "x-agent-parent-step"
)

// ===== 下行 Header（Gateway → Client）=====
const (
	HeaderSessionRiskScore = "x-agent-session-risk-score"
	HeaderGuardAction      = "x-agent-guard-action"
	HeaderRemainingSteps   = "x-agent-session-remaining-steps"
	HeaderRemainingTokens  = "x-agent-session-remaining-tokens"
	HeaderGuardMode        = "x-agent-guard-mode"
)

// ===== 工作模式 =====
const (
	ModeFull     = "full"
	ModeDegraded = "degraded"
)

// ===== Context Keys =====
const (
	CtxKeyRequestState = "agent_guard_request_state"
)

// ===== Dynamic Metadata 命名空间 =====
const (
	MetadataNamespaceAgentGuard  = "agent_guard"
	MetadataNamespaceSecurityEvt = "security_events"
)

func main() {}

func init() {
	wrapper.SetCtx(
		pluginName,
		wrapper.ParseConfig(config.ParseConfig),
		wrapper.ProcessRequestHeaders(onHttpRequestHeaders),
		wrapper.ProcessRequestBody(onHttpRequestBody),
		wrapper.ProcessResponseHeaders(onHttpResponseHeaders),
		wrapper.ProcessResponseBody(onHttpResponseBody),
		wrapper.ProcessStreamingResponseBody(onHttpStreamingResponseBody),
	)
}

// onHttpRequestHeaders 请求头阶段：提取 Session ID、校验、确定模式、读取 Session 状态
func onHttpRequestHeaders(ctx wrapper.HttpContext, cfg config.AgentGuardConfig) types.Action {
	ctx.DisableReroute()

	// 提取上行 Header
	rs := extractRequestHeaders(ctx)

	// 提取 Session ID
	sessionID, err := proxywasm.GetHttpRequestHeader(HeaderSessionID)
	if err != nil || sessionID == "" {
		// No Session header: create a queryable degraded session for ordinary single-turn requests.
		rs.SessionID = generateFallbackSessionID()
		rs.Mode = ModeDegraded
		rs.IdentityTrusted, rs.UserID, rs.UserName, rs.UserDept, rs.UserRole =
			extractTrustedIdentity(&cfg)
		extractIdentityFields(rs)
		rs.EventKey = generateEventKey(rs.SessionID)
		publishAgentGuardMetadata(rs)
		ctx.SetContext(CtxKeyRequestState, rs)
		injectDownstreamModeHeader(ModeDegraded)
		log.Debugf("no session id header, generated fallback session %s and working in degraded mode", rs.SessionID)
		return types.ActionContinue
	}

	rs.SessionID = sessionID

	// 校验 Session ID
	if cfg.SessionIDSecurity.ValidationEnabled {
		if valid, reason := validateSessionID(sessionID, &cfg); !valid {
			rs.Mode = handleValidationFailure(&cfg, reason)
			rs.IdentityTrusted, rs.UserID, rs.UserName, rs.UserDept, rs.UserRole =
				extractTrustedIdentity(&cfg)
			extractIdentityFields(rs)
			rs.EventKey = generateEventKey(sessionID)
			publishAgentGuardMetadata(rs)
			ctx.SetContext(CtxKeyRequestState, rs)
			injectDownstreamModeHeader(rs.Mode)
			if rs.Mode == "" {
				// reject 模式：直接拒绝请求
				sendBlockResponse(ctx, &cfg, 403, "Session ID validation failed: "+reason)
				return types.ActionContinue
			}
			return types.ActionContinue
		}
	}

	rs.Mode = ModeFull
	ctx.SetContext(CtxKeyRequestState, rs)

	// 身份信任校验 + 提取（方案 4.1）
	// 未通过校验时：IdentityTrusted=false, UserID="untrusted_anonymous", UserRole="guest"
	rs.IdentityTrusted, rs.UserID, rs.UserName, rs.UserDept, rs.UserRole =
		extractTrustedIdentity(&cfg)
	// 智能体拓扑信息（非敏感，直接透传）
	extractIdentityFields(rs)
	ctx.SetContext(CtxKeyRequestState, rs)

	// 生成 Event Key 并通过 Dynamic Metadata 共享给安全插件
	rs.EventKey = generateEventKey(sessionID)
	publishAgentGuardMetadata(rs)

	// 完整模式：从 Redis 读取 Session meta
	// 先检查熔断器状态
	if !globalCircuitBreaker.AllowRedisRequest(&cfg) {
		// 熔断器打开，根据配置降级或拒绝
		if cfg.RedisFailAction == "block" {
			sendBlockResponse(ctx, &cfg, 503, "Redis circuit breaker open")
			return types.ActionContinue
		}
		rs.Mode = ModeDegraded
		ctx.SetContext(CtxKeyRequestState, rs)
		injectDownstreamModeHeader(ModeDegraded)
		log.Warnf("redis circuit breaker open, degrading to single-request mode")
		return types.ActionContinue
	}

	if !cfg.RedisClient.Ready() {
		// Redis 不可用，记录熔断失败
		globalCircuitBreaker.RecordRedisFailure(&cfg)
		if cfg.RedisFailAction == "block" {
			sendBlockResponse(ctx, &cfg, 503, "Redis unavailable, agent guard cannot work")
			return types.ActionContinue
		}
		// 降级为单请求模式
		rs.Mode = ModeDegraded
		ctx.SetContext(CtxKeyRequestState, rs)
		injectDownstreamModeHeader(ModeDegraded)
		log.Warnf("redis not ready, degrading to single-request mode")
		return types.ActionContinue
	}

	// 黑名单检查（方案 3.3.7）：必须在 SessionMeta 读取前执行，基于 UserID/AgentID 直接判定
	// 命中黑名单 → 直接拦截；未命中 → 继续 readSessionMeta
	checkBlacklist(&cfg, rs, func(blocked bool, reason string) {
		if blocked {
			sendBlockResponse(ctx, &cfg, 403, "Blacklisted: "+reason)
			proxywasm.ResumeHttpRequest()
			return
		}
		// 黑名单未命中，异步读取 Session meta
		readSessionMetaAndContinue(&cfg, rs, ctx)
	})

	return types.HeaderStopAllIterationAndWatermark
}

// readSessionMetaAndContinue 读取 Session meta 并执行后续限制/限流/高危复检
func readSessionMetaAndContinue(cfg *config.AgentGuardConfig, rs *RequestState, ctx wrapper.HttpContext) {
	if err := readSessionMeta(cfg, rs, func(meta *SessionMeta, readErr error) {
		if readErr != nil {
			log.Warnf("read session meta failed: %v, degrading", readErr)
			globalCircuitBreaker.RecordRedisFailure(cfg)
			rs.Mode = ModeDegraded
			ctx.SetContext(CtxKeyRequestState, rs)
			injectDownstreamModeHeader(ModeDegraded)
			proxywasm.ResumeHttpRequest()
			return
		}

		// Redis 读取成功，记录熔断成功
		globalCircuitBreaker.RecordRedisSuccess()

		rs.SessionMeta = meta

		// 检查 Session 限制
		if action := checkSessionLimits(cfg, meta); action != "" {
			// 触发限制，拦截请求
			sendBlockResponse(ctx, cfg, 429, action)
			proxywasm.ResumeHttpRequest()
			return
		}

		// 高危 Session：实时黑名单复检（绕过缓存，方案 3.3.7）
		// 防止 Session 首个请求 RiskScore=0 时黑名单用户第一波攻击被放行后的逃逸
		if isHighRiskSession(rs) {
			checkBlacklistRealtime(cfg, rs, func(rtBlocked bool, rtReason string) {
				if rtBlocked {
					sendBlockResponse(ctx, cfg, 403, "Blacklisted: "+rtReason)
					proxywasm.ResumeHttpRequest()
					return
				}
				// 检查 Session 级限流（滑动窗口）
				checkSessionRateLimit(cfg, rs, ctx)
			})
			return
		}

		// 非高危：直接限流检查
		checkSessionRateLimit(cfg, rs, ctx)
	}); err != nil {
		log.Errorf("redis read session meta failed: %v", err)
		globalCircuitBreaker.RecordRedisFailure(cfg)
		// Redis 调用失败，降级
		rs.Mode = ModeDegraded
		ctx.SetContext(CtxKeyRequestState, rs)
		injectDownstreamModeHeader(ModeDegraded)
		proxywasm.ResumeHttpRequest()
	}
}

// checkSessionRateLimit 检查 Session 级限流（滑动窗口）
// 在 readSessionMeta 回调中调用，检查通过后恢复请求
func checkSessionRateLimit(cfg *config.AgentGuardConfig, rs *RequestState, ctx wrapper.HttpContext) {
	key := fmt.Sprintf(RedisKeyReqWindow, rs.SessionID)
	keys := []interface{}{key}
	args := []interface{}{60, cfg.SessionLimits.MaxRequestsPerMinute} // 1 分钟窗口

	err := cfg.RedisClient.Eval(luaCheckRateLimit, 1, keys, args, func(response resp.Value) {
		arr := response.Array()
		if len(arr) < 2 {
			log.Warnf("rate limit check response invalid, allowing request")
			proxywasm.ResumeHttpRequest()
			return
		}

		current := arr[0].Integer()
		allowed := arr[1].Integer()

		if allowed == 0 {
			// 触发限流
			log.Warnf("session rate limit exceeded: session=%s current=%d", rs.SessionID, current)
			sendBlockResponse(ctx, cfg, 429, "Session rate limit exceeded")
			proxywasm.ResumeHttpRequest()
			return
		}

		// 限流通过，恢复请求
		proxywasm.ResumeHttpRequest()
	})

	if err != nil {
		log.Warnf("rate limit check failed: %v, allowing request", err)
		proxywasm.ResumeHttpRequest()
	}
}

// onHttpRequestBody 请求体阶段：记录请求元信息
func onHttpRequestBody(ctx wrapper.HttpContext, cfg config.AgentGuardConfig, body []byte) types.Action {
	rs, ok := ctx.GetContext(CtxKeyRequestState).(*RequestState)
	if !ok || rs == nil {
		return types.ActionContinue
	}

	// 记录请求体元信息（模型、消息数等）
	recordRequestMetadata(rs, body)

	return types.ActionContinue
}

// onHttpResponseHeaders 响应头阶段：收集安全事件、计算风险、更新 Session、注入下行 Header
func onHttpResponseHeaders(ctx wrapper.HttpContext, cfg config.AgentGuardConfig) types.Action {
	rs, ok := ctx.GetContext(CtxKeyRequestState).(*RequestState)
	if !ok || rs == nil {
		return types.ActionContinue
	}

	// 降级模式：收集安全事件 + 注入模式标识 + 行为风险打分
	if rs.Mode == ModeDegraded {
		injectDownstreamModeHeader(ModeDegraded)
		// 捕获响应状态码（供 onHttpResponseBody 中 inferSecurityEventsFromResponse 使用）
		if statusStr, err := proxywasm.GetHttpResponseHeader(":status"); err == nil && statusStr != "" {
			if code, err := strconv.Atoi(statusStr); err == nil {
				rs.ResponseStatus = code
			}
		}
		// 降级模式：从 ai-pii-guard 响应头收集 PII 事件（跨 VM 保底方案）
		collectPIIEventsFromHeaders(rs)
		// 降级模式仍收集安全事件（由上游安全插件写入 Dynamic Metadata）
		if len(rs.Events) == 0 {
			rs.Events = collectSecurityEvents(rs)
		}
		// 降级模式仍做行为风险打分（随审计日志写入，供后端分析）
		rs.BehaviorRiskScore = detectBehaviorRisk(&cfg, rs)
		return types.ActionContinue
	}

	// 记录响应开始时间（用于计算 ResponseLatency）
	rs.ResponseStartTime = time.Now().UnixMilli()

	// 完整模式：从 ai-pii-guard 响应头收集 PII 事件（跨 VM 保底方案）
	collectPIIEventsFromHeaders(rs)

	// 完整模式：收集安全事件
	events := collectSecurityEvents(rs)
	// 合并：如果 collectSecurityEvents 也返回了事件（Dynamic Metadata 可用），追加到已有事件
	if len(events) > 0 && len(rs.Events) > 0 {
		rs.Events = append(rs.Events, events...)
	} else if len(events) > 0 {
		rs.Events = events
	}
	events = rs.Events

	// 计算风险增量
	rs.RiskIncrement = calculateRiskIncrement(&cfg, events, rs)

	// 行为风险实时打分（方案 4.4：纯内存计算，不写告警，随审计日志写入）
	rs.BehaviorRiskScore = detectBehaviorRisk(&cfg, rs)

	// 如果 Redis 不可用或熔断器打开或无需更新，直接注入 Header
	if !cfg.RedisClient.Ready() || !globalCircuitBreaker.AllowRedisRequest(&cfg) || rs.SessionMeta == nil {
		injectDownstreamHeaders(rs, &cfg)
		return types.ActionContinue
	}

	// 异步更新 Session 状态（Lua 原子更新）
	if err := updateSessionMeta(&cfg, rs, func(newRiskScore int, updateErr error) {
		if updateErr != nil {
			log.Warnf("update session meta failed: %v", updateErr)
			globalCircuitBreaker.RecordRedisFailure(&cfg)
		} else {
			globalCircuitBreaker.RecordRedisSuccess()
			if rs.SessionMeta != nil {
				rs.SessionMeta.RiskScore = newRiskScore
			}
		}

		// 注入下行 Header
		injectDownstreamHeaders(rs, &cfg)

		proxywasm.ResumeHttpResponse()
	}); err != nil {
		log.Errorf("redis update session meta failed: %v", err)
		globalCircuitBreaker.RecordRedisFailure(&cfg)
		injectDownstreamHeaders(rs, &cfg)
		return types.ActionContinue
	}

	return types.HeaderStopAllIterationAndWatermark
}

// onHttpStreamingResponseBody 流式响应体阶段：捕获 token 用量，结束时写入审计日志
func onHttpStreamingResponseBody(ctx wrapper.HttpContext, cfg config.AgentGuardConfig, chunk []byte, endOfStream bool) []byte {
	rs, ok := ctx.GetContext(CtxKeyRequestState).(*RequestState)
	if !ok || rs == nil {
		return chunk
	}

	// 捕获 token 用量（从流式响应的最后一个 chunk）
	if endOfStream {
		captureTokenUsage(rs, chunk)
		// 累加到 Session token 配额
		incrementSessionTokens(&cfg, rs)

		// 兜底收集安全事件（确保 onHttpResponseHeaders 未触发时也能收集）
		if len(rs.Events) == 0 {
			rs.Events = collectSecurityEvents(rs)
		}

		// 根据响应状态码推断安全事件
		inferSecurityEventsFromResponse(rs)

		// 在流结束时写入审计日志（此时 token 用量已捕获）
		writeAuditLog(ctx, &cfg, rs)
	}

	return chunk
}

// onHttpResponseBody 非流式响应体阶段（如本地403拦截响应）：记录响应体大小并写入审计日志
func onHttpResponseBody(ctx wrapper.HttpContext, cfg config.AgentGuardConfig, body []byte) types.Action {
	rs, ok := ctx.GetContext(CtxKeyRequestState).(*RequestState)
	if !ok || rs == nil {
		return types.ActionContinue
	}
	rs.ResponseBodySize = int64(len(body))
	// 收集安全事件（本地响应可能跳过 onHttpResponseHeaders，在此兜底收集）
	if len(rs.Events) == 0 {
		rs.Events = collectSecurityEvents(rs)
	}
	// 根据响应状态码推断安全事件（Wasm 插件 Dynamic Metadata 不跨 VM 共享的兜底方案）
	inferSecurityEventsFromResponse(rs)
	// 非流式响应：从 JSON body 解析 token 用量并累加到 Session 配额
	captureTokenUsageFromBody(rs, body)
	incrementSessionTokens(&cfg, rs)
	// 非流式响应（如安全插件拦截的本地响应）：直接写入审计日志
	writeAuditLog(ctx, &cfg, rs)
	return types.ActionContinue
}

// captureTokenUsageFromBody 非流式响应中解析 token 用量（OpenAI chat completions usage 字段）
func captureTokenUsageFromBody(rs *RequestState, body []byte) {
	if len(body) == 0 || rs.ResponseCaptured {
		return
	}
	usage := gjson.GetBytes(body, "usage")
	if usage.Exists() {
		in := usage.Get("prompt_tokens").Int()
		out := usage.Get("completion_tokens").Int()
		if in > 0 || out > 0 {
			rs.InputToken = in
			rs.OutputToken = out
			rs.ResponseCaptured = true
			log.Debugf("captured token usage from non-streaming body: input=%d output=%d", rs.InputToken, rs.OutputToken)
		}
	}
}

// inferSecurityEventsFromResponse 根据响应状态码和响应头推断安全事件
// 由于 Wasm 插件运行在独立 VM 中，Dynamic Metadata 不跨插件共享，
// ai-prompt-guard/ai-pii-guard 写入的 security_events metadata 无法被 ai-agent-guard 读取。
// 此函数通过检查响应状态码和响应头来推断安全事件：
// - 403 且非 ai-agent-guard 自身拦截 → 推断为 prompt_injection（由 ai-prompt-guard 拦截）
// - x-pii-detected 响应头存在 → 推断为 pii_leak（由 ai-pii-guard 检测并脱敏）
// 注意：PII 检测(200脱敏通过)和提示注入检测(403拦截)可同时存在于同一请求
func inferSecurityEventsFromResponse(rs *RequestState) {
	// 记录推断前的事件数量；若来自 Dynamic Metadata，后续不再推断 inject
	preExistingCount := len(rs.Events)

	// === PII 检测推断（通过 ai-pii-guard 设置的 x-pii-detected 响应头） ===
	if piiHeader, err := proxywasm.GetHttpResponseHeader("x-pii-detected"); err == nil && piiHeader != "" {
		if !hasEventType(rs.Events, "pii_leak") {
			rs.Events = append(rs.Events, SecurityEvent{
				Type:     "pii_leak",
				Severity: "medium",
				Source:   "ai-pii-guard",
				Score:    60,
				Detail:   "PII detected and masked in request: " + piiHeader,
			})
			log.Debugf("inferSecurityEventsFromResponse: inferred pii_leak event from x-pii-detected header: %s", piiHeader)
		}
	}

	// === 提示注入推断（通过响应状态码 403） ===
	// 若事件已在 onHttpResponseHeaders 中通过 Dynamic Metadata 收集到，跳过推断避免覆盖
	if preExistingCount > 0 {
		return
	}
	// 如果是 ai-agent-guard 自身拦截的（rs.Blocked=true），不推断
	if rs.Blocked {
		return
	}

	// 尝试获取响应状态码
	statusCode := rs.ResponseStatus
	if statusCode == 0 {
		if statusStr, err := proxywasm.GetHttpResponseHeader(":status"); err == nil && statusStr != "" {
			if statusStr == "403" {
				statusCode = 403
			}
		}
	}

	if statusCode != 403 {
		return
	}

	// 403 且非自身拦截 → 推断为 prompt_injection（由 ai-prompt-guard 拦截）
	rs.Events = append(rs.Events, SecurityEvent{
		Type:     "prompt_injection",
		Severity: "high",
		Source:   "ai-prompt-guard",
		Score:    80,
		Detail:   "Detected prompt injection / jailbreak pattern in user message",
	})
	// 更新拦截标记
	rs.Blocked = true
	rs.ResponseStatus = 403
	log.Warnf("inferSecurityEventsFromResponse: inferred prompt_injection event")
}

// hasEventType 检查事件列表中是否已包含指定类型的事件（避免重复添加）
func hasEventType(events []SecurityEvent, eventType string) bool {
	for _, e := range events {
		if e.Type == eventType {
			return true
		}
	}
	return false
}

// collectPIIEventsFromHeaders 从 ai-pii-guard 设置的 x-pii-detected 响应头收集 PII 事件
// 由于 Wasm VM 隔离，Dynamic Metadata 可能不跨插件共享。
// ai-pii-guard 在 onHttpRequestBody 检测到 PII 后会暂存匹配规则，
// 在 onHttpResponseHeaders 中设置 x-pii-detected 响应头供本插件读取。
func collectPIIEventsFromHeaders(rs *RequestState) {
	piiHeader, err := proxywasm.GetHttpResponseHeader("x-pii-detected")
	if err != nil || piiHeader == "" {
		return
	}
	if hasEventType(rs.Events, "pii_leak") {
		return
	}
	rs.Events = append(rs.Events, SecurityEvent{
		Type:     "pii_leak",
		Severity: "medium",
		Source:   "ai-pii-guard",
		Score:    60,
		Detail:   "PII detected and masked in request: " + piiHeader,
	})
	log.Debugf("collectPIIEventsFromHeaders: detected PII rules=%s from x-pii-detected header", piiHeader)
}

// extractRequestHeaders 从请求头提取 Agent 执行链信息
func extractRequestHeaders(ctx wrapper.HttpContext) *RequestState {
	rs := &RequestState{}

	if v, err := proxywasm.GetHttpRequestHeader(HeaderStepIndex); err == nil {
		rs.StepIndex = v
	}
	if v, err := proxywasm.GetHttpRequestHeader(HeaderStepType); err == nil {
		rs.StepType = v
	}
	if v, err := proxywasm.GetHttpRequestHeader(HeaderToolName); err == nil {
		rs.ToolName = v
	}
	if v, err := proxywasm.GetHttpRequestHeader(HeaderToolParamsHash); err == nil {
		rs.ToolParamsHash = v
	}
	if v, err := proxywasm.GetHttpRequestHeader(HeaderParentStep); err == nil {
		rs.ParentStep = v
	}

	return rs
}

// injectDownstreamModeHeader 注入工作模式标识
func injectDownstreamModeHeader(mode string) {
	_ = proxywasm.AddHttpResponseHeader(HeaderGuardMode, mode)
}

// injectDownstreamHeaders 注入所有下行 Header
func injectDownstreamHeaders(rs *RequestState, cfg *config.AgentGuardConfig) {
	// 工作模式
	_ = proxywasm.AddHttpResponseHeader(HeaderGuardMode, rs.Mode)

	if rs.SessionMeta == nil {
		return
	}

	// 风险评分
	riskScore := rs.SessionMeta.RiskScore
	_ = proxywasm.AddHttpResponseHeader(HeaderSessionRiskScore, intToString(riskScore))

	// 触发动作
	action := determineAction(&cfg.RiskScoring, riskScore)
	if action != "" {
		_ = proxywasm.AddHttpResponseHeader(HeaderGuardAction, action)
	}

	// 剩余步数
	remainingSteps := cfg.SessionLimits.MaxStepsPerSession - rs.SessionMeta.StepCount
	if remainingSteps < 0 {
		remainingSteps = 0
	}
	_ = proxywasm.AddHttpResponseHeader(HeaderRemainingSteps, intToString(remainingSteps))

	// 剩余 Token
	remainingTokens := cfg.SessionLimits.MaxTokensPerSession - rs.SessionMeta.TokenCount
	if remainingTokens < 0 {
		remainingTokens = 0
	}
	_ = proxywasm.AddHttpResponseHeader(HeaderRemainingTokens, int64ToString(remainingTokens))
}

// sendBlockResponse 发送拦截响应，同时收集安全事件并写入审计日志
func sendBlockResponse(ctx wrapper.HttpContext, cfg *config.AgentGuardConfig, statusCode int, message string) {
	rs, ok := ctx.GetContext(CtxKeyRequestState).(*RequestState)
	if ok && rs != nil {
		rs.Blocked = true
		rs.ResponseStatus = statusCode
		// 尝试读取安全插件已写入的事件
		rs.Events = collectSecurityEvents(rs)
		writeAuditLog(ctx, cfg, rs)
	}

	headers := [][2]string{
		{"content-type", "application/json"},
	}
	body := `{"error":{"message":"` + message + `","type":"agent_guard_error","code":"session_blocked"}}`
	proxywasm.SendHttpResponse(uint32(statusCode), headers, []byte(body), -1)
}

// intToString 整数转字符串
func intToString(v int) string {
	return fmtInt(int64(v))
}

// int64ToString int64 转字符串
func int64ToString(v int64) string {
	return fmtInt(v)
}
