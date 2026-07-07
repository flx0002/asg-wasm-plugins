package main

import (
	"ai-agent-guard/config"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/resp"
)

// 审计日志字段最大长度
const (
	MaxFieldLength  = 512 // 单字段截断长度
	MaxDetailLength = 256 // 事件详情截断长度
	MaxEventsPerLog = 20  // 单条日志最大事件数
)

// AuditLogEntry 审计日志条目（写入 ai_log 和 Redis）
type AuditLogEntry struct {
	EventId          string       `json:"event_id"`
	Timestamp        int64        `json:"timestamp"`
	TimestampMs      int64        `json:"timestamp_ms"`
	SessionID        string       `json:"session_id"`
	Mode             string       `json:"mode"`
	Model            string       `json:"model"`
	StepIndex        string       `json:"step_index"`
	StepType         string       `json:"step_type"`
	ToolName         string       `json:"tool_name"`
	ToolParamsHash   string       `json:"tool_params_hash"`
	RiskScore        int          `json:"risk_score"`
	RiskScoreBefore  int          `json:"risk_score_before"`
	RiskIncrement    int          `json:"risk_increment"`
	Action           string       `json:"action"`
	InputToken       int64        `json:"input_token"`
	OutputToken      int64        `json:"output_token"`
	Events           []AuditEvent `json:"events"`
	RequestBodyHash  string       `json:"request_body_hash"`
	RequestBodySize  int64        `json:"request_body_size"`
	ResponseStatus   int          `json:"response_status"`
	ResponseBodySize int64        `json:"response_body_size"`
	Blocked          bool         `json:"blocked"`
	RecordTypes      []string     `json:"record_types"`
	HighRisk         bool         `json:"high_risk"`

	// === 行为分析：身份与行为字段 ===
	IdentityTrusted   bool   `json:"identity_trusted"`
	UserID            string `json:"user_id"`
	UserName          string `json:"user_name"`
	UserDept          string `json:"user_dept"`
	UserRole          string `json:"user_role"`
	AgentID           string `json:"agent_id"`
	AgentOwner        string `json:"agent_owner"`
	AgentType         string `json:"agent_type"`
	SourceIP          string `json:"source_ip"`
	UserAgent         string `json:"user_agent"`
	TraceID           string `json:"trace_id"`
	ParentStep        string `json:"parent_step"`
	ToolCallID        string `json:"tool_call_id"`
	RetrievalID       string `json:"retrieval_id"`
	KnowledgeBaseID   string `json:"knowledge_base_id"`
	ResponseLatency   int64  `json:"response_latency"`
	BehaviorRiskScore int    `json:"behavior_risk_score"`
	BusinessObject    string `json:"business_object"` // 预留字段（见 1.2 声明）
}

// AuditEvent 审计日志中的安全事件（已脱敏）
type AuditEvent struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Score    int    `json:"score"`
	Detail   string `json:"detail"` // 已脱敏、截断
}

// writeAuditLog 写入审计日志到 ai_log 和 Redis
func writeAuditLog(ctx wrapper.HttpContext, cfg *config.AgentGuardConfig, rs *RequestState) {
	if rs == nil || rs.AuditWritten {
		return
	}
	rs.AuditWritten = true

	entry := buildAuditEntry(cfg, rs)

	// 1. 写入 ai_log（已有逻辑，保留）
	ctx.SetUserAttribute("agent_guard_audit", serializeAuditEntry(entry))
	_ = ctx.WriteUserAttributeToLogWithKey(wrapper.AILogKey)

	// 2. 写入 Redis（新增）
	effectiveCfg := config.GetEffectiveConfig(&cfg.AuditChain)
	if !effectiveCfg.Enabled || !shouldRecord(effectiveCfg, rs) {
		return
	}
	if cfg.RedisClient.Ready() {
		writeAuditToRedis(cfg, effectiveCfg, rs, entry)
	}
}

// shouldRecord 根据配置判断是否需要记录该请求
func shouldRecord(cfg *config.AuditChain, rs *RequestState) bool {
	types := determineRecordTypes(rs)
	for _, t := range types {
		switch t {
		case "normal":
			if cfg.RecordTypes.Normal {
				return true
			}
		case "blocked":
			if cfg.RecordTypes.Blocked {
				return true
			}
		case "degraded":
			if cfg.RecordTypes.Degraded {
				return true
			}
		case "security_event":
			if cfg.RecordTypes.SecurityEvent {
				return true
			}
		}
	}
	return false
}

// determineRecordTypes 判断请求的记录类型标签
func determineRecordTypes(rs *RequestState) []string {
	types := []string{}
	if rs.Blocked {
		types = append(types, "blocked")
	}
	if rs.Mode == ModeDegraded {
		types = append(types, "degraded")
	}
	if len(rs.Events) > 0 {
		types = append(types, "security_event")
	}
	if len(types) == 0 {
		types = append(types, "normal")
	}
	return types
}

// isHighRisk 判断是否为高风险请求
func isHighRisk(rs *RequestState, entry AuditLogEntry) bool {
	if rs.Blocked {
		return true
	}
	if rs.SessionMeta != nil && rs.SessionMeta.RiskScore >= 80 {
		return true
	}
	for _, e := range rs.Events {
		if e.Severity == "high" {
			return true
		}
	}
	return false
}

// 行为分析索引 Key 常量（方案 3.3.6 / 3.3.8）
const (
	RedisKeyAuditUserIndex  = "agent_audit:user:%s"
	RedisKeyAuditAgentIndex = "agent_audit:agent:%s"
	RedisKeyUntrustedBucket = "agent_audit:user:untrusted_anonymous"
	RedisKeyCallersWindow   = "agent_behavior:callers:%s"

	// 调用者窗口 TTL：10 分钟（覆盖 5min 检测窗口 × 2 余量）
	callersWindowTTL = 600
	// 未信任聚合桶 TTL：1 天
	untrustedBucketTTL = 86400
)

// writeAuditToRedis 写入审计日志到 Redis 二级索引
func writeAuditToRedis(cfg *config.AgentGuardConfig, auditCfg *config.AuditChain, rs *RequestState, entry AuditLogEntry) {
	eventId := entry.EventId
	if eventId == "" {
		eventId = generateEventId()
		entry.EventId = eventId
	}

	// 降级模式处理：为无 Session 的请求生成虚拟 Session ID，避免降级日志丢失
	// 按小时聚合降级请求，例如：degraded_20241018_15
	sessionId := rs.SessionID
	if sessionId == "" {
		sessionId = fmt.Sprintf("degraded_%s", time.Now().Format("20060102_15"))
		entry.SessionID = sessionId // 同步更新 entry，确保 JSON 中 session_id 不为空
	}

	zsetKey := fmt.Sprintf("agent_audit:%s", sessionId)
	logKey := fmt.Sprintf("agent_audit_log:%s", eventId)
	data := serializeAuditEntry(entry)
	score := float64(entry.TimestampMs*1000 + int64(rs.Sequence%1000))
	fallbackTTL := computeFallbackTTL(auditCfg.Retention.MaxDays)

	// 身份维度索引 Key 计算（方案 3.3.6）
	// 信任用户 → 按 userId 建独立索引；未信任 → 统一入 untrusted_anonymous 桶
	userKey := ""
	untrustedFlag := "0"
	if rs.IdentityTrusted && rs.UserID != "" {
		userKey = fmt.Sprintf(RedisKeyAuditUserIndex, rs.UserID)
	} else if !rs.IdentityTrusted {
		userKey = RedisKeyUntrustedBucket
		untrustedFlag = "1"
	}

	// 智能体维度索引（方案 3.3.6）
	agentKey := ""
	if rs.AgentID != "" {
		agentKey = fmt.Sprintf(RedisKeyAuditAgentIndex, rs.AgentID)
	}

	// 调用者滑动窗口（方案 3.3.8）
	callersKey := ""
	if rs.AgentID != "" {
		callersKey = fmt.Sprintf(RedisKeyCallersWindow, rs.AgentID)
	}
	// 调用者窗口 member：userId，缺失时用 untrusted_anonymous
	callersMember := rs.UserID
	if callersMember == "" {
		callersMember = UntrustedUserID
	}

	// Lua 脚本：先写详情，再写索引（避免脏索引），使用 pcall 容错
	err := cfg.RedisClient.Eval(luaAppendAuditLog, 5,
		[]interface{}{zsetKey, logKey, userKey, agentKey, callersKey},
		[]interface{}{eventId, data, score, fallbackTTL,
			callersMember, entry.TimestampMs, callersWindowTTL,
			untrustedFlag, untrustedBucketTTL},
		func(response resp.Value) {
			ret := response.String()
			if ret == "-1" {
				log.Warnf("audit log detail write failed (redis may be full), event_id=%s", eventId)
			} else {
				log.Debugf("audit log written to redis, event_id=%s, session_count=%s", eventId, ret)
			}
		})
	if err != nil {
		log.Warnf("eval audit lua script failed: %v, event_id=%s", err, eventId)
	}
}

// generateEventId 生成事件 ID
// 格式：{毫秒时间戳}-{6位随机 hex}
func generateEventId() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b))
}

// computeFallbackTTL 计算兜底 TTL（秒）
// max_days > 0 时：fallback_ttl = max_days*2+7 天
// max_days = 0 时（不清理）：fallback_ttl = 180 天（合规上限）
func computeFallbackTTL(maxDays int) int {
	if maxDays <= 0 {
		return 180 * 86400
	}
	return (maxDays*2 + 7) * 86400
}

func deduplicateSecurityEvents(events []SecurityEvent) []SecurityEvent {
	if len(events) <= 1 {
		return events
	}
	seen := make(map[string]struct{}, len(events))
	result := make([]SecurityEvent, 0, len(events))
	for _, event := range events {
		key := event.Type + "\x00" + event.Source + "\x00" + event.Severity + "\x00" + event.Detail
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, event)
	}
	return result
}

// buildAuditEntry 构建审计日志条目（含脱敏和体积控制）
func buildAuditEntry(cfg *config.AgentGuardConfig, rs *RequestState) AuditLogEntry {
	now := time.Now()
	entry := AuditLogEntry{
		EventId:          generateEventId(),
		Timestamp:        now.Unix(),
		TimestampMs:      now.UnixMilli(),
		SessionID:        rs.SessionID,
		Mode:             rs.Mode,
		Model:            rs.Model,
		StepIndex:        rs.StepIndex,
		StepType:         rs.StepType,
		ToolName:         rs.ToolName,
		ToolParamsHash:   rs.ToolParamsHash,
		RiskIncrement:    rs.RiskIncrement,
		InputToken:       rs.InputToken,
		OutputToken:      rs.OutputToken,
		RequestBodySize:  rs.RequestBodySize,
		ResponseBodySize: rs.ResponseBodySize,
		ResponseStatus:   rs.ResponseStatus,
		Blocked:          rs.Blocked,
	}

	// 风险评分
	riskScoreBefore := 0
	if rs.SessionMeta != nil {
		entry.RiskScore = rs.SessionMeta.RiskScore
		riskScoreBefore = rs.SessionMeta.RiskScore - rs.RiskIncrement
		if riskScoreBefore < 0 {
			riskScoreBefore = 0
		}
	}
	entry.RiskScoreBefore = riskScoreBefore

	// 触发动作
	entry.Action = determineAction(&cfg.RiskScoring, entry.RiskScore)

	// 安全事件（脱敏 + 截断 + 数量限制）
	events := deduplicateSecurityEvents(rs.Events)
	eventCount := len(events)
	if eventCount > MaxEventsPerLog {
		eventCount = MaxEventsPerLog
	}
	entry.Events = make([]AuditEvent, 0, eventCount)
	for i := 0; i < eventCount; i++ {
		e := events[i]
		entry.Events = append(entry.Events, AuditEvent{
			Type:     e.Type,
			Severity: e.Severity,
			Source:   e.Source,
			Score:    e.Score,
			Detail:   truncateAndSanitize(e.Detail, MaxDetailLength),
		})
	}

	// 请求体哈希（不记录原文）
	if rs.RequestBodySize > 0 {
		entry.RequestBodyHash = rs.ToolParamsHash // 复用已有的参数哈希
	}

	// 记录类型标签
	entry.RecordTypes = determineRecordTypes(rs)

	// 高风险标记
	entry.HighRisk = isHighRisk(rs, entry)

	// === 行为分析：身份与行为字段 ===
	entry.IdentityTrusted = rs.IdentityTrusted
	entry.UserID = rs.UserID
	entry.UserName = rs.UserName
	entry.UserDept = rs.UserDept
	entry.UserRole = rs.UserRole
	entry.AgentID = rs.AgentID
	entry.AgentOwner = rs.AgentOwner
	entry.AgentType = rs.AgentType
	entry.SourceIP = rs.SourceIP
	entry.UserAgent = rs.UserAgent
	entry.TraceID = rs.TraceID
	entry.ParentStep = rs.ParentStep
	entry.ToolCallID = rs.ToolCallID
	entry.RetrievalID = rs.RetrievalID
	entry.KnowledgeBaseID = rs.KnowledgeBaseID
	entry.BehaviorRiskScore = rs.BehaviorRiskScore

	// 响应延迟（毫秒），需在 ResponseStartTime 已设置时计算
	if rs.ResponseStartTime > 0 {
		entry.ResponseLatency = now.UnixMilli() - rs.ResponseStartTime
	}

	return entry
}

// serializeAuditEntry 序列化审计日志条目
func serializeAuditEntry(entry AuditLogEntry) string {
	// verbose 级别记录完整信息
	// standard 级别省略部分字段
	// minimal 级别仅记录核心字段
	data, err := json.Marshal(entry)
	if err != nil {
		log.Warnf("marshal audit entry failed: %v", err)
		return ""
	}
	return string(data)
}

// truncateAndSanitize 截断并脱敏字符串
func truncateAndSanitize(s string, maxLen int) string {
	if len(s) == 0 {
		return ""
	}

	// 脱敏：移除可能的 PII 模式（简化版）
	sanitized := sanitizePII(s)

	// 截断
	if len(sanitized) > maxLen {
		sanitized = sanitized[:maxLen] + "..."
	}

	return sanitized
}

// sanitizePII 简单 PII 脱敏
// 对邮箱、手机号、身份证号等常见 PII 进行掩码处理
func sanitizePII(s string) string {
	// 邮箱脱敏
	s = maskEmail(s)
	// 手机号脱敏
	s = maskPhone(s)
	// 身份证号脱敏
	s = maskIDCard(s)
	return s
}

// maskEmail 邮箱脱敏：保留首字符和域名
func maskEmail(s string) string {
	// 简化实现：匹配 xxx@xxx.xxx 格式
	atIdx := strings.Index(s, "@")
	if atIdx <= 0 {
		return s
	}
	dotIdx := strings.LastIndex(s[atIdx:], ".")
	if dotIdx <= 0 {
		return s
	}
	if atIdx == 1 {
		return s[:1] + "***" + s[atIdx:]
	}
	return s[:1] + "***" + s[atIdx:]
}

// maskPhone 手机号脱敏：保留前3后4
func maskPhone(s string) string {
	if len(s) < 11 {
		return s
	}
	// 简化处理，仅对纯数字11位字符串脱敏
	allDigit := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allDigit = false
			break
		}
	}
	if !allDigit || len(s) != 11 {
		return s
	}
	return s[:3] + "****" + s[7:]
}

// maskIDCard 身份证号脱敏：保留前6后4
func maskIDCard(s string) string {
	if len(s) < 15 {
		return s
	}
	// 简化处理
	if len(s) == 18 || len(s) == 15 {
		return s[:6] + "********" + s[len(s)-4:]
	}
	return s
}

// hashContent 计算内容哈希（用于审计日志中记录 Thought 等敏感内容的指纹）
func hashContent(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}
