package main

import (
	"ai-agent-guard/config"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/tidwall/gjson"
	"github.com/tidwall/resp"
)

// Redis Key 格式
const (
	RedisKeySessionMeta  = "agent_session:%s:meta"
	RedisKeySessionSteps = "agent_session:%s:steps"
	RedisKeyReqWindow    = "agent_session:%s:req_window"
	RedisKeyEvent        = "agent_event:%s"
)

// Session meta Hash 字段名
const (
	MetaFieldRiskScore      = "risk_score"
	MetaFieldRequestCount   = "request_count"
	MetaFieldStepCount      = "step_count"
	MetaFieldTokenCount     = "token_count"
	MetaFieldViolationCount = "violation_count"
	MetaFieldLastActiveTime = "last_active_time"
	MetaFieldCreatedAt      = "created_at"
)

// UUID v4 格式正则（小写）
var uuidV4Regex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Session ID 格式正则：{prefix}_{uuid_v4}
var sessionIDRegex = regexp.MustCompile(`^[a-z0-9-]+_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// validateSessionID 校验 Session ID 的格式、长度、签名、prefix 白名单
// 返回 (是否有效, 失败原因)
func generateFallbackSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(now >> uint((i%8)*8))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	uuid := hex.EncodeToString(b)
	return fmt.Sprintf("auto-agent_%s-%s-%s-%s-%s",
		uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
}

func validateSessionID(sessionID string, cfg *config.AgentGuardConfig) (bool, string) {
	// 长度校验
	if len(sessionID) > 128 {
		return false, "session id exceeds 128 characters"
	}

	// 格式校验：必须匹配 {prefix}_{uuid_v4}
	if !sessionIDRegex.MatchString(sessionID) {
		return false, "session id format invalid, expected {prefix}_{uuid_v4}"
	}

	// prefix 提取
	parts := strings.SplitN(sessionID, "_", 2)
	if len(parts) != 2 {
		return false, "session id missing prefix"
	}
	prefix := parts[0]

	// prefix 白名单校验
	if len(cfg.SessionIDSecurity.PrefixWhitelist) > 0 {
		allowed := false
		for _, p := range cfg.SessionIDSecurity.PrefixWhitelist {
			if p == prefix {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, "session id prefix not in whitelist"
		}
	}

	// 签名校验
	if cfg.SessionIDSecurity.SignatureEnabled {
		if cfg.SessionIDSecurity.SignatureSecret == "" {
			return false, "signature enabled but secret not configured"
		}
		// 签名通过 x-agent-session-sig Header 传递
		sig, err := proxywasm.GetHttpRequestHeader("x-agent-session-sig")
		if err != nil || sig == "" {
			return false, "signature header missing"
		}
		if !verifyHMAC(sessionID, sig, cfg.SessionIDSecurity.SignatureSecret) {
			return false, "signature verification failed"
		}
	}

	return true, ""
}

// verifyHMAC 验证 HMAC-SHA256 签名
func verifyHMAC(message, signature, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// handleValidationFailure 根据配置处理校验失败
// 返回工作模式（degrade 表示降级，空字符串表示拒绝）
func handleValidationFailure(cfg *config.AgentGuardConfig, reason string) string {
	switch cfg.SessionIDSecurity.OnValidationFailure {
	case "reject":
		log.Warnf("session id rejected: %s", reason)
		return ""
	case "log_only":
		log.Warnf("session id validation failed but continuing: %s", reason)
		return ModeFull
	case "degrade":
		log.Warnf("session id validation failed, degrading: %s", reason)
		return ModeDegraded
	default:
		return ModeDegraded
	}
}

// generateEventKey 生成事件收集用的 Event Key（用于 Redis 保底方案）
func generateEventKey(sessionID string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", sessionID[:min(len(sessionID), 16)], hex.EncodeToString(b))
}

// publishAgentGuardMetadata 通过 Dynamic Metadata 发布 Agent Guard 信息给安全插件
func publishAgentGuardMetadata(rs *RequestState) {
	// 使用 SetProperty 设置 Dynamic Metadata，安全插件可通过 GetProperty 读取
	metadata := fmt.Sprintf(`{"session_id":"%s","event_key":"%s","mode":"%s","step_index":"%s","step_type":"%s","tool_name":"%s"}`,
		rs.SessionID, rs.EventKey, rs.Mode, rs.StepIndex, rs.StepType, rs.ToolName)
	if err := proxywasm.SetProperty([]string{MetadataNamespaceAgentGuard, "context"}, []byte(metadata)); err != nil {
		log.Warnf("set agent_guard metadata failed: %v", err)
	}
}

// readSessionMeta 从 Redis 读取 Session 元数据
func readSessionMeta(cfg *config.AgentGuardConfig, rs *RequestState, callback func(*SessionMeta, error)) error {
	key := fmt.Sprintf(RedisKeySessionMeta, rs.SessionID)
	fields := []string{
		MetaFieldRiskScore,
		MetaFieldRequestCount,
		MetaFieldStepCount,
		MetaFieldTokenCount,
		MetaFieldViolationCount,
		MetaFieldLastActiveTime,
		MetaFieldCreatedAt,
	}

	return cfg.RedisClient.HMGet(key, fields, func(response resp.Value) {
		arr := response.Array()
		if len(arr) != len(fields) {
			// Session 不存在，返回空 meta
			now := time.Now().Unix()
			callback(&SessionMeta{
				CreatedAt:      now,
				LastActiveTime: now,
			}, nil)
			return
		}

		meta := &SessionMeta{}
		for i, v := range arr {
			if v.IsNull() {
				continue
			}
			switch fields[i] {
			case MetaFieldRiskScore:
				meta.RiskScore = int(v.Integer())
			case MetaFieldRequestCount:
				meta.RequestCount = int(v.Integer())
			case MetaFieldStepCount:
				meta.StepCount = int(v.Integer())
			case MetaFieldTokenCount:
				meta.TokenCount = int64(v.Integer())
			case MetaFieldViolationCount:
				meta.ViolationCount = int(v.Integer())
			case MetaFieldLastActiveTime:
				meta.LastActiveTime = int64(v.Integer())
			case MetaFieldCreatedAt:
				meta.CreatedAt = int64(v.Integer())
			}
		}

		// 如果 CreatedAt 为 0，说明是新 Session
		if meta.CreatedAt == 0 {
			now := time.Now().Unix()
			meta.CreatedAt = now
			meta.LastActiveTime = now
		}

		callback(meta, nil)
	})
}

// checkSessionLimits 检查 Session 级限制
// 返回非空字符串表示触发限制的原因（用于拦截），空字符串表示通过
func checkSessionLimits(cfg *config.AgentGuardConfig, meta *SessionMeta) string {
	// 风险评分阈值检查
	if meta.RiskScore >= cfg.SessionLimits.RiskScoreThreshold {
		return "session risk score exceeded threshold"
	}

	// 最大违规次数检查
	if meta.ViolationCount >= cfg.SessionLimits.MaxViolations {
		return "session violation count exceeded limit"
	}

	// 最大步数检查
	if meta.StepCount >= cfg.SessionLimits.MaxStepsPerSession {
		return "session step count exceeded limit"
	}

	// Token 配额检查
	if meta.TokenCount >= cfg.SessionLimits.MaxTokensPerSession {
		return "session token quota exhausted"
	}

	return ""
}

// updateSessionMeta 使用 Lua 脚本原子更新 Session 状态
func updateSessionMeta(cfg *config.AgentGuardConfig, rs *RequestState, callback func(int, error)) error {
	key := fmt.Sprintf(RedisKeySessionMeta, rs.SessionID)
	now := time.Now().Unix()

	// Lua 脚本参数：
	// ARGV[1] = 当前时间戳（秒）
	// ARGV[2] = 衰减时间常数 τ（秒）
	// ARGV[3] = 风险增量
	// ARGV[4] = Token 增量
	// ARGV[5] = Session 超时时间（秒）
	args := []interface{}{
		now,
		cfg.RiskScoring.DecayTau,
		rs.RiskIncrement,
		rs.InputToken + rs.OutputToken,
		cfg.SessionLimits.SessionTimeout,
	}

	return cfg.RedisClient.Eval(luaUpdateSessionMeta, 1, []interface{}{key}, args, func(response resp.Value) {
		if response.IsNull() {
			callback(0, fmt.Errorf("lua update returned null"))
			return
		}
		newRiskScore := int(response.Integer())
		callback(newRiskScore, nil)
	})
}

// recordRequestMetadata 记录请求体元信息
func recordRequestMetadata(rs *RequestState, body []byte) {
	if len(body) == 0 {
		return
	}
	rs.RequestBodySize = int64(len(body))

	// 从请求体中提取模型名（OpenAI 格式）
	if model := gjson.GetBytes(body, "model"); model.Exists() {
		rs.Model = model.String()
	}
}

// captureTokenUsage 从 SSE 流式响应中捕获 Token 用量
// OpenAI 格式：data: {"usage":{"prompt_tokens":N,"completion_tokens":M,"total_tokens":T}}
func captureTokenUsage(rs *RequestState, chunk []byte) {
	if len(chunk) == 0 {
		return
	}

	// SSE 格式：每行以 "data: " 开头
	// 最后一个包含 usage 的 chunk 通常是：data: {"id":"...","choices":[],"usage":{...}}
	chunkStr := string(chunk)

	// 逐行解析 SSE 数据
	for _, line := range strings.Split(chunkStr, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			continue
		}

		// 解析 JSON，查找 usage 字段
		usage := gjson.Get(data, "usage")
		if usage.Exists() {
			rs.InputToken = usage.Get("prompt_tokens").Int()
			rs.OutputToken = usage.Get("completion_tokens").Int()
			log.Debugf("captured token usage: input=%d output=%d", rs.InputToken, rs.OutputToken)
		}
	}

	rs.ResponseCaptured = true
}

// determineAction 根据风险评分确定触发动作
func determineAction(riskCfg *config.RiskScoring, score int) string {
	if score >= riskCfg.Thresholds.High {
		return riskCfg.Actions.High
	}
	if score >= riskCfg.Thresholds.Medium {
		return riskCfg.Actions.Medium
	}
	return ""
}

// fmtInt int64 转字符串
func fmtInt(v int64) string {
	return strconv.FormatInt(v, 10)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
