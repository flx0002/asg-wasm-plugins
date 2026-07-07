package main

import (
	"ai-agent-guard/config"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/tidwall/gjson"
)

// ===== 身份相关上行 Header（Client → Gateway）=====
const (
	HeaderMASUserID   = "x-mas-user-id"
	HeaderMASUserName = "x-mas-user-name"
	HeaderMASUserDept = "x-mas-user-dept"
	HeaderMASUserRole = "x-mas-user-role"

	HeaderUserID   = "x-user-id"
	HeaderUserName = "x-user-name"
	HeaderUserDept = "x-user-dept"
	HeaderUserRole = "x-user-role"
	HeaderUserSig  = "x-user-sig"
	HeaderUserTS   = "x-user-ts"

	HeaderAgentID     = "x-agent-id"
	HeaderAgentOwner  = "x-agent-owner"
	HeaderAgentType   = "x-agent-type"
	HeaderTraceID     = "x-trace-id"
	HeaderToolCallID  = "x-agent-tool-call-id"
	HeaderRetrievalID = "x-agent-retrieval-id"
	HeaderKBID        = "x-agent-kb-id"

	HeaderXForwardedFor = "x-forwarded-for"
	HeaderXRealIP       = "x-real-ip"
)

// 未信任请求的统一身份标识
const (
	UntrustedUserID   = "untrusted_anonymous"
	UntrustedUserName = "匿名用户"
	UntrustedUserDept = "unknown"
	UntrustedUserRole = "guest"
)

// HMAC 时间戳防重放容差（秒）
const hmacTimestampTolerance = 300

// extractTrustedIdentity 按 cfg.IdentityTrust.Mode 校验身份来源可信度（方案 4.1）
//
// 返回 (trusted, userId, userName, userDept, userRole)。
// 未通过校验时统一返回 untrusted_anonymous / guest，不阻断请求。
func extractTrustedIdentity(cfg *config.AgentGuardConfig) (trusted bool, uid, name, dept, role string) {
	switch cfg.IdentityTrust.Mode {
	case "gateway":
		return extractIdentityGateway(cfg)
	case "header_hmac":
		return extractIdentityHeaderHMAC(cfg)
	case "jwt_inline":
		return extractIdentityJWTInline(cfg)
	default: // "off"
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}
}

// extractIdentityGateway gateway 模式：强制校验来源 IP 命中 InternalCIDRs 白名单
// 内部标记 Header 仅作辅助佐证，CIDR 不命中即视为未信任
func extractIdentityGateway(cfg *config.AgentGuardConfig) (trusted bool, uid, name, dept, role string) {
	clientIP := extractClientIP()
	if !isSourceIPInCIDRs(cfg.IdentityTrust.InternalCIDRs, clientIP) {
		log.Debugf("gateway mode: source ip %s not in internal cidrs, marking untrusted", clientIP)
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}
	return true,
		getHeaderOrDefault(HeaderMASUserID, "anonymous"),
		getHeaderOrDefault(HeaderMASUserName, ""),
		getHeaderOrDefault(HeaderMASUserDept, ""),
		getHeaderOrDefault(HeaderMASUserRole, "guest")
}

// extractIdentityHeaderHMAC header_hmac 模式：HMAC-SHA256 验签 + 时间戳防重放
// 签名覆盖 payload = uid + role + agentId + ts，密钥取 cfg.IdentityTrust.HmacSecret
func extractIdentityHeaderHMAC(cfg *config.AgentGuardConfig) (trusted bool, uid, name, dept, role string) {
	uid = getHeaderOrDefault(HeaderUserID, "")
	role = getHeaderOrDefault(HeaderUserRole, "guest")
	name = getHeaderOrDefault(HeaderUserName, "")
	dept = getHeaderOrDefault(HeaderUserDept, "")
	agentID := getHeaderOrDefault(HeaderAgentID, "")
	sig := getHeaderOrDefault(HeaderUserSig, "")
	tsStr := getHeaderOrDefault(HeaderUserTS, "")

	if uid == "" || sig == "" || tsStr == "" {
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}

	// 防重放：timestamp 偏差 > 5 分钟即拒绝（无需 Redis 去重）
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > hmacTimestampTolerance {
		log.Debugf("header_hmac mode: timestamp out of tolerance, ts=%d now=%d", ts, now)
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}

	// HMAC 验签：payload = uid + role + agentId + ts
	payload := uid + role + agentID + tsStr
	if !verifyHMAC(payload, sig, cfg.IdentityTrust.HmacSecret) {
		log.Debugf("header_hmac mode: hmac verification failed for uid=%s", uid)
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}

	return true, uid, name, dept, role
}

// extractIdentityJWTInline jwt_inline 模式：解析 JWT 并校验 exp/nbf
//
// 注意：完整 JWKS 验签需复用 jwt-auth 插件能力（方案 4.1 说明）。
// 当前实现解码 JWT payload 并执行 exp/nbf 时效校验，签名验证依赖部署侧
// 由 jwt-auth 插件先行验签。若未配置 JWKS 或 JWT 结构无效，返回未信任。
func extractIdentityJWTInline(cfg *config.AgentGuardConfig) (trusted bool, uid, name, dept, role string) {
	if cfg.IdentityTrust.JwksUrl == "" {
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}

	// 从 Authorization: Bearer <jwt> 提取
	authz := getHeaderOrDefault("authorization", "")
	if authz == "" {
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}
	token := authz
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		token = strings.TrimSpace(authz[7:])
	}

	claims, err := parseJWTClaims(token)
	if err != nil {
		log.Debugf("jwt_inline mode: parse jwt failed: %v", err)
		return false, UntrustedUserID, UntrustedUserName, UntrustedUserDept, UntrustedUserRole
	}

	return true, claims.sub, claims.name, claims.dept, claims.role
}

// jwtClaims JWT payload 中提取的身份字段
type jwtClaims struct {
	sub  string
	name string
	dept string
	role string
}

// parseJWTClaims 解析 JWT 并校验 exp/nbf，提取身份 claims
// JWT 结构：header.payload.signature（均为 base64url 无填充）
func parseJWTClaims(token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt format")
	}

	// 解码 payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload failed: %w", err)
	}

	// 使用 gjson 解析 claims（复用已有依赖）
	return parseAndValidateClaims(payload)
}

// extractIdentityFields 从 Header 提取智能体拓扑信息与行为追踪字段（方案 4.1）
// 这些字段非敏感，直接透传，不依赖身份信任校验结果
func extractIdentityFields(rs *RequestState) {
	// AgentID 缺省取 SessionID 前 8 字符
	defaultAgentID := rs.SessionID
	if len(defaultAgentID) > 8 {
		defaultAgentID = defaultAgentID[:8]
	}

	rs.AgentID = getHeaderOrDefault(HeaderAgentID, defaultAgentID)
	// AgentOwner 缺省取 UserID（信任校验后）
	rs.AgentOwner = getHeaderOrDefault(HeaderAgentOwner, rs.UserID)
	rs.AgentType = getHeaderOrDefault(HeaderAgentType, "chat")
	rs.TraceID = extractTraceID()
	rs.ToolCallID = getHeaderOrDefault(HeaderToolCallID, "")
	rs.RetrievalID = getHeaderOrDefault(HeaderRetrievalID, "")
	rs.KnowledgeBaseID = getHeaderOrDefault(HeaderKBID, "")
	rs.SourceIP = extractClientIP()
	rs.UserAgent = truncateString(getHeaderOrDefault("user-agent", ""), 256)
}

// extractClientIP 提取客户端真实 IP（X-Forwarded-For 首个 → X-Real-IP）
func extractClientIP() string {
	if v, err := proxywasm.GetHttpRequestHeader(HeaderXForwardedFor); err == nil && v != "" {
		// X-Forwarded-For: client, proxy1, proxy2
		if idx := strings.Index(v, ","); idx > 0 {
			return strings.TrimSpace(v[:idx])
		}
		return strings.TrimSpace(v)
	}
	if v, err := proxywasm.GetHttpRequestHeader(HeaderXRealIP); err == nil && v != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

// extractTraceID 提取 W3C Trace ID（traceparent 首选，x-trace-id 兜底）
func extractTraceID() string {
	// W3C traceparent: 00-<trace-id>-<span-id>-<flags>
	if v, err := proxywasm.GetHttpRequestHeader("traceparent"); err == nil && v != "" {
		parts := strings.Split(v, "-")
		if len(parts) >= 3 && len(parts[1]) == 32 {
			return parts[1]
		}
	}
	if v, err := proxywasm.GetHttpRequestHeader(HeaderTraceID); err == nil && v != "" {
		return v
	}
	return ""
}

// getHeaderOrDefault 读取请求 Header，缺失时返回默认值
func getHeaderOrDefault(name, def string) string {
	v, err := proxywasm.GetHttpRequestHeader(name)
	if err != nil || v == "" {
		return def
	}
	return v
}

// truncateString 截断字符串到指定长度
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// isSourceIPInCIDRs 校验来源 IP 是否命中 CIDR 白名单（方案 4.1）
// 支持 IPv4，CIDR 格式为 "1.2.3.0/24"；单 IP 视为 /32
func isSourceIPInCIDRs(cidrs []string, ip string) bool {
	if ip == "" {
		return false
	}
	ipUint, ok := parseIPv4(ip)
	if !ok {
		return false
	}
	for _, cidr := range cidrs {
		if cidr == "" {
			continue
		}
		prefix := uint32(32)
		network := cidr
		if idx := strings.Index(cidr, "/"); idx >= 0 {
			network = cidr[:idx]
			if p, err := strconv.Atoi(cidr[idx+1:]); err == nil && p >= 0 && p <= 32 {
				prefix = uint32(p)
			}
		}
		netUint, ok := parseIPv4(network)
		if !ok {
			continue
		}
		// 计算掩码：prefix 位全 1
		var mask uint32
		if prefix == 0 {
			mask = 0
		} else {
			mask = ^uint32(0) << (32 - prefix)
		}
		if (ipUint & mask) == (netUint & mask) {
			return true
		}
	}
	return false
}

// parseIPv4 将点分十进制 IPv4 转为 uint32
func parseIPv4(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var result uint32
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return 0, false
		}
		result = (result << 8) | uint32(v)
	}
	return result, true
}

// parseAndValidateClaims 解析 JWT payload JSON 并校验 exp/nbf，提取身份 claims
// claims 字段映射：sub→uid, name→name, dept→dept, role→role
func parseAndValidateClaims(payload []byte) (*jwtClaims, error) {
	result := gjson.ParseBytes(payload)

	// exp 校验：过期则拒绝
	if exp := result.Get("exp"); exp.Exists() {
		expTime := exp.Int()
		if time.Now().Unix() >= expTime {
			return nil, fmt.Errorf("jwt expired")
		}
	}
	// nbf 校验：生效前则拒绝
	if nbf := result.Get("nbf"); nbf.Exists() {
		nbfTime := nbf.Int()
		if time.Now().Unix() < nbfTime {
			return nil, fmt.Errorf("jwt not yet valid")
		}
	}

	return &jwtClaims{
		sub:  result.Get("sub").String(),
		name: result.Get("name").String(),
		dept: result.Get("dept").String(),
		role: result.Get("role").String(),
	}, nil
}
