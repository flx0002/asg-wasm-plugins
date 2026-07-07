package config

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
)

// AgentGuardConfig ai-agent-guard 插件配置
type AgentGuardConfig struct {
	// Redis 配置
	RedisClient wrapper.RedisClient

	// Session 限制
	SessionLimits SessionLimits

	// 风险评分配置
	RiskScoring RiskScoring

	// 安全事件收集配置
	EventCollection EventCollection

	// 审计日志配置
	Audit Audit

	// 全链路审计配置
	AuditChain AuditChain

	// 熔断器配置
	CircuitBreaker CircuitBreaker

	// Session ID 安全配置
	SessionIDSecurity SessionIDSecurity

	// 工具策略配置
	ToolPolicy ToolPolicy

	// 行为分析：身份信任配置
	IdentityTrust IdentityTrust

	// 降级行为配置
	RedisFailAction     string // degrade | block
	SecurityFailAction  string // pass | block | degrade
}

// SessionLimits Session 级限制配置
type SessionLimits struct {
	MaxRequestsPerMinute int   // 单 Session 每分钟最大请求数
	MaxRequestsPerHour   int   // 单 Session 每小时最大请求数
	MaxTokensPerSession  int64 // 单 Session 最大 token 消耗
	MaxStepsPerSession   int   // 单 Session 最大步数
	SessionTimeout       int   // Session 超时时间（秒）
	RiskScoreThreshold   int   // 风险评分阈值，超过后拦截后续请求
	MaxViolations        int   // 最大违规次数，超过后终止 Session
}

// RiskScoring 风险评分配置
type RiskScoring struct {
	BaseWeights     map[string]int // 基础分值
	BehaviorWeights map[string]int // 行为模式分值
	Thresholds      RiskThresholds // 风险阈值
	Actions         RiskActions    // 触发动作
	DecayTau        int            // 衰减时间常数（秒）
}

// RiskThresholds 风险阈值
type RiskThresholds struct {
	Low    int
	Medium int
	High   int
}

// RiskActions 触发动作
type RiskActions struct {
	Medium   string // alert
	High     string // enhance
	Critical string // block
}

// EventCollection 安全事件收集配置
type EventCollection struct {
	// 事件传递方式：dynamic_metadata（首选）| redis（保底）
	PreferredMethod string
	// Redis Event Key TTL（秒），仅 Redis 方案使用
	EventKeyTTL int
}

// Audit 审计日志配置
type Audit struct {
	LogLevel string // minimal | standard | verbose
}

// AuditChain 全链路审计配置
type AuditChain struct {
	Enabled     bool
	RecordTypes RecordTypes
	Retention   Retention
}

// RecordTypes 记录类型开关
type RecordTypes struct {
	Normal        bool
	Blocked       bool
	Degraded      bool
	SecurityEvent bool
}

// Retention 保留策略
type Retention struct {
	MaxDays              int // 热数据保留天数，0=不清理，最大 180
	MaxEntriesPerSession int // 单 Session 最大条数
	// FallbackTTL 由 MaxDays 自动计算，不作为配置项
}

// AuditConfigCache 审计配置热更新缓存（VM 级别）
type AuditConfigCache struct {
	mu            sync.Mutex
	config        *AuditChain
	version       int64
	lastCheckTime int64
}

// GlobalAuditConfigCache 全局审计配置缓存（每个 Wasm VM 独立）
var GlobalAuditConfigCache = &AuditConfigCache{}

// NeedsRefresh 检查是否需要刷新（TTL=10s）
func (c *AuditConfigCache) NeedsRefresh() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Unix()-c.lastCheckTime > 10
}

// Get 获取缓存的审计配置（如果存在）
func (c *AuditConfigCache) Get() *AuditChain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.config
}

// Update 更新缓存
func (c *AuditConfigCache) Update(cfg *AuditChain, version int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = cfg
	c.version = version
	c.lastCheckTime = time.Now().Unix()
}

// MarkChecked 标记已检查（即使没有更新也刷新检查时间）
func (c *AuditConfigCache) MarkChecked() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastCheckTime = time.Now().Unix()
}

// GetEffectiveConfig 获取生效的审计配置（优先使用 Redis 运行时配置，其次 Wasm 本地配置）
func GetEffectiveConfig(staticCfg *AuditChain) *AuditChain {
	cached := GlobalAuditConfigCache.Get()
	if cached != nil {
		return cached
	}
	return staticCfg
}

// CircuitBreaker 熔断器配置
type CircuitBreaker struct {
	Redis    CircuitBreakerConfig
	PolicyAPI CircuitBreakerConfig
}

// CircuitBreakerConfig 单个熔断器配置
type CircuitBreakerConfig struct {
	FailureThreshold int // 连续失败次数阈值
	RecoveryTimeout  int // 恢复探测间隔（秒）
	HalfOpenMaxCalls int // 半开状态最大探测次数
}

// SessionIDSecurity Session ID 安全配置
type SessionIDSecurity struct {
	ValidationEnabled     bool
	OnValidationFailure   string // reject | degrade | log_only
	SignatureEnabled      bool
	SignatureSecret       string
	SignatureAlgorithm    string
	PrefixWhitelist       []string
}

// ToolPolicy 工具策略配置
type ToolPolicy struct {
	DefaultAction  string      // deny | allow
	Tools          []ToolRule  // 工具规则列表
}

// ToolRule 单个工具规则
type ToolRule struct {
	Name              string
	Allowed           bool
	MaxCallsPerSession int
	HighRisk          bool
	RiskDeltaOnCall   int
}

// IdentityTrust 行为分析身份信任配置
type IdentityTrust struct {
	Mode          string   // gateway | header_hmac | jwt_inline | off
	InternalCIDRs []string // gateway 模式必须的来源 IP 白名单
	HmacSecret    string   // header_hmac 模式专用 HMAC 密钥
	JwksUrl       string   // jwt_inline 模式专用 JWKS 公钥 URL
}

// ParseConfig 解析插件配置
func ParseConfig(json gjson.Result, config *AgentGuardConfig) error {
	// 设置默认值
	setDefaults(config)

	// 解析 Redis 配置
	if err := initRedis(json, config); err != nil {
		log.Warnf("redis init failed: %v, will work in degraded mode", err)
	}

	// 解析 Session 限制
	parseSessionLimits(json, config)

	// 解析风险评分配置
	parseRiskScoring(json, config)

	// 解析事件收集配置
	parseEventCollection(json, config)

	// 解析审计配置
	parseAudit(json, config)

	// 解析全链路审计配置
	parseAuditChain(json, config)

	// 解析熔断器配置
	parseCircuitBreaker(json, config)

	// 解析 Session ID 安全配置
	parseSessionIDSecurity(json, config)

	// 解析工具策略
	parseToolPolicy(json, config)

	// 解析身份信任配置
	parseIdentityTrust(json, config)

	// 解析降级行为
	parseFailActions(json, config)

	return nil
}

func setDefaults(config *AgentGuardConfig) {
	// Session 限制默认值
	config.SessionLimits = SessionLimits{
		MaxRequestsPerMinute: 30,
		MaxRequestsPerHour:   200,
		MaxTokensPerSession:  500000,
		MaxStepsPerSession:   50,
		SessionTimeout:       3600,
		RiskScoreThreshold:   60,
		MaxViolations:        5,
	}

	// 风险评分默认值
	config.RiskScoring = RiskScoring{
		BaseWeights: map[string]int{
			"prompt_injection":         30,
			"content_violation_high":   25,
			"content_violation_medium": 15,
			"pii_leak":                 20,
			"content_mask":             10,
		},
		BehaviorWeights: map[string]int{
			"request_frequency_anomaly":  20,
			"message_length_escalation":  15,
			"tool_sequence_anomaly":      20,
			"context_window_approaching": 10,
		},
		Thresholds: RiskThresholds{
			Low:    20,
			Medium: 50,
			High:   80,
		},
		Actions: RiskActions{
			Medium:   "alert",
			High:     "enhance",
			Critical: "block",
		},
		DecayTau: 600,
	}

	// 事件收集默认值
	config.EventCollection = EventCollection{
		PreferredMethod: "dynamic_metadata",
		EventKeyTTL:     300,
	}

	// 审计默认值
	config.Audit = Audit{
		LogLevel: "standard",
	}

	// 全链路审计默认值
	config.AuditChain = AuditChain{
		Enabled: true,
		RecordTypes: RecordTypes{
			Normal:        true,
			Blocked:       true,
			Degraded:      true,
			SecurityEvent: true,
		},
		Retention: Retention{
			MaxDays:              7,
			MaxEntriesPerSession: 1000,
		},
	}

	// 熔断器默认值
	config.CircuitBreaker = CircuitBreaker{
		Redis: CircuitBreakerConfig{
			FailureThreshold: 5,
			RecoveryTimeout:  30,
			HalfOpenMaxCalls: 3,
		},
		PolicyAPI: CircuitBreakerConfig{
			FailureThreshold: 3,
			RecoveryTimeout:  60,
			HalfOpenMaxCalls: 2,
		},
	}

	// Session ID 安全默认值
	config.SessionIDSecurity = SessionIDSecurity{
		ValidationEnabled:   true,
		OnValidationFailure: "degrade",
	}

	// 工具策略默认值
	config.ToolPolicy = ToolPolicy{
		DefaultAction: "deny",
	}

	// 身份信任默认值
	config.IdentityTrust = IdentityTrust{
		Mode: "gateway",
	}

	// 降级行为默认值
	config.RedisFailAction = "degrade"
	config.SecurityFailAction = "pass"
}

func initRedis(json gjson.Result, config *AgentGuardConfig) error {
	redisConfig := json.Get("redis")
	if !redisConfig.Exists() {
		return errors.New("missing redis in config")
	}

	serviceName := redisConfig.Get("service_name").String()
	if serviceName == "" {
		return errors.New("redis service name must not be empty")
	}

	servicePort := int(redisConfig.Get("service_port").Int())
	if servicePort == 0 {
		if strings.HasSuffix(serviceName, ".static") {
			servicePort = 80
		} else {
			servicePort = 6379
		}
	}

	username := redisConfig.Get("username").String()
	password := redisConfig.Get("password").String()
	timeout := int(redisConfig.Get("timeout").Int())
	if timeout == 0 {
		timeout = 1000
	}

	config.RedisClient = wrapper.NewRedisClusterClient(wrapper.FQDNCluster{
		FQDN: serviceName,
		Port: int64(servicePort),
	})
	database := int(redisConfig.Get("database").Int())
	err := config.RedisClient.Init(username, password, int64(timeout), wrapper.WithDataBase(database))
	if config.RedisClient.Ready() {
		log.Info("ai-agent-guard redis init successfully")
	} else {
		log.Error("ai-agent-guard redis init failed, will work in degraded mode")
	}
	return err
}

func parseSessionLimits(json gjson.Result, config *AgentGuardConfig) {
	sl := json.Get("session_limits")
	if !sl.Exists() {
		return
	}

	if v := sl.Get("max_requests_per_minute"); v.Exists() {
		config.SessionLimits.MaxRequestsPerMinute = int(v.Int())
	}
	if v := sl.Get("max_requests_per_hour"); v.Exists() {
		config.SessionLimits.MaxRequestsPerHour = int(v.Int())
	}
	if v := sl.Get("max_tokens_per_session"); v.Exists() {
		config.SessionLimits.MaxTokensPerSession = v.Int()
	}
	if v := sl.Get("max_steps_per_session"); v.Exists() {
		config.SessionLimits.MaxStepsPerSession = int(v.Int())
	}
	if v := sl.Get("session_timeout"); v.Exists() {
		config.SessionLimits.SessionTimeout = int(v.Int())
	}
	if v := sl.Get("risk_score_threshold"); v.Exists() {
		config.SessionLimits.RiskScoreThreshold = int(v.Int())
	}
	if v := sl.Get("max_violations"); v.Exists() {
		config.SessionLimits.MaxViolations = int(v.Int())
	}
}

func parseRiskScoring(json gjson.Result, config *AgentGuardConfig) {
	rs := json.Get("risk_scoring")
	if !rs.Exists() {
		return
	}

	// 解析基础分值
	if bw := rs.Get("base_weights"); bw.Exists() {
		bw.ForEach(func(key, value gjson.Result) bool {
			config.RiskScoring.BaseWeights[key.String()] = int(value.Int())
			return true
		})
	}

	// 解析行为模式分值
	if bww := rs.Get("behavior_weights"); bww.Exists() {
		bww.ForEach(func(key, value gjson.Result) bool {
			config.RiskScoring.BehaviorWeights[key.String()] = int(value.Int())
			return true
		})
	}

	// 解析阈值
	if th := rs.Get("thresholds"); th.Exists() {
		if v := th.Get("low"); v.Exists() {
			config.RiskScoring.Thresholds.Low = int(v.Int())
		}
		if v := th.Get("medium"); v.Exists() {
			config.RiskScoring.Thresholds.Medium = int(v.Int())
		}
		if v := th.Get("high"); v.Exists() {
			config.RiskScoring.Thresholds.High = int(v.Int())
		}
	}

	// 解析动作
	if act := rs.Get("actions"); act.Exists() {
		if v := act.Get("medium"); v.Exists() {
			config.RiskScoring.Actions.Medium = v.String()
		}
		if v := act.Get("high"); v.Exists() {
			config.RiskScoring.Actions.High = v.String()
		}
		if v := act.Get("critical"); v.Exists() {
			config.RiskScoring.Actions.Critical = v.String()
		}
	}

	// 解析衰减时间常数
	if v := rs.Get("decay_tau"); v.Exists() {
		config.RiskScoring.DecayTau = int(v.Int())
	}
}

func parseEventCollection(json gjson.Result, config *AgentGuardConfig) {
	ec := json.Get("event_collection")
	if !ec.Exists() {
		return
	}

	if v := ec.Get("preferred_method"); v.Exists() {
		config.EventCollection.PreferredMethod = v.String()
	}
	if v := ec.Get("event_key_ttl"); v.Exists() {
		config.EventCollection.EventKeyTTL = int(v.Int())
	}
}

func parseAudit(json gjson.Result, config *AgentGuardConfig) {
	audit := json.Get("audit")
	if !audit.Exists() {
		return
	}

	if v := audit.Get("log_level"); v.Exists() {
		config.Audit.LogLevel = v.String()
	}
}

func parseAuditChain(json gjson.Result, config *AgentGuardConfig) {
	ac := json.Get("audit_chain")
	if !ac.Exists() {
		return
	}

	if v := ac.Get("enabled"); v.Exists() {
		config.AuditChain.Enabled = v.Bool()
	}

	if rt := ac.Get("record_types"); rt.Exists() {
		if v := rt.Get("normal"); v.Exists() {
			config.AuditChain.RecordTypes.Normal = v.Bool()
		}
		if v := rt.Get("blocked"); v.Exists() {
			config.AuditChain.RecordTypes.Blocked = v.Bool()
		}
		if v := rt.Get("degraded"); v.Exists() {
			config.AuditChain.RecordTypes.Degraded = v.Bool()
		}
		if v := rt.Get("security_event"); v.Exists() {
			config.AuditChain.RecordTypes.SecurityEvent = v.Bool()
		}
	}

	if r := ac.Get("retention"); r.Exists() {
		if v := r.Get("max_days"); v.Exists() {
			maxDays := int(v.Int())
			if maxDays > 180 {
				maxDays = 180
			}
			config.AuditChain.Retention.MaxDays = maxDays
		}
		if v := r.Get("max_entries_per_session"); v.Exists() {
			config.AuditChain.Retention.MaxEntriesPerSession = int(v.Int())
		}
	}
}

func parseCircuitBreaker(json gjson.Result, config *AgentGuardConfig) {
	cb := json.Get("circuit_breaker")
	if !cb.Exists() {
		return
	}

	if redisCB := cb.Get("redis"); redisCB.Exists() {
		if v := redisCB.Get("failure_threshold"); v.Exists() {
			config.CircuitBreaker.Redis.FailureThreshold = int(v.Int())
		}
		if v := redisCB.Get("recovery_timeout"); v.Exists() {
			config.CircuitBreaker.Redis.RecoveryTimeout = int(v.Int())
		}
		if v := redisCB.Get("half_open_max_calls"); v.Exists() {
			config.CircuitBreaker.Redis.HalfOpenMaxCalls = int(v.Int())
		}
	}

	if apiCB := cb.Get("policy_api"); apiCB.Exists() {
		if v := apiCB.Get("failure_threshold"); v.Exists() {
			config.CircuitBreaker.PolicyAPI.FailureThreshold = int(v.Int())
		}
		if v := apiCB.Get("recovery_timeout"); v.Exists() {
			config.CircuitBreaker.PolicyAPI.RecoveryTimeout = int(v.Int())
		}
		if v := apiCB.Get("half_open_max_calls"); v.Exists() {
			config.CircuitBreaker.PolicyAPI.HalfOpenMaxCalls = int(v.Int())
		}
	}
}

func parseSessionIDSecurity(json gjson.Result, config *AgentGuardConfig) {
	sis := json.Get("session_id_security")
	if !sis.Exists() {
		return
	}

	if v := sis.Get("validation.enabled"); v.Exists() {
		config.SessionIDSecurity.ValidationEnabled = v.Bool()
	}
	if v := sis.Get("validation.on_validation_failure"); v.Exists() {
		config.SessionIDSecurity.OnValidationFailure = v.String()
	}
	if v := sis.Get("signature.enabled"); v.Exists() {
		config.SessionIDSecurity.SignatureEnabled = v.Bool()
	}
	if v := sis.Get("signature.secret"); v.Exists() {
		config.SessionIDSecurity.SignatureSecret = v.String()
	}
	if v := sis.Get("signature.algorithm"); v.Exists() {
		config.SessionIDSecurity.SignatureAlgorithm = v.String()
	}
	if v := sis.Get("prefix_whitelist"); v.Exists() {
		for _, item := range v.Array() {
			config.SessionIDSecurity.PrefixWhitelist = append(config.SessionIDSecurity.PrefixWhitelist, item.String())
		}
	}
}

func parseToolPolicy(json gjson.Result, config *AgentGuardConfig) {
	tp := json.Get("tool_policy")
	if !tp.Exists() {
		return
	}

	if v := tp.Get("default_action"); v.Exists() {
		config.ToolPolicy.DefaultAction = v.String()
	}

	if tools := tp.Get("tools"); tools.Exists() {
		for _, tool := range tools.Array() {
			rule := ToolRule{
				Name:              tool.Get("name").String(),
				Allowed:           tool.Get("allowed").Bool(),
				MaxCallsPerSession: int(tool.Get("max_calls_per_session").Int()),
				HighRisk:          tool.Get("high_risk").Bool(),
				RiskDeltaOnCall:   int(tool.Get("risk_delta_on_call").Int()),
			}
			if rule.MaxCallsPerSession == 0 {
				rule.MaxCallsPerSession = 10
			}
			config.ToolPolicy.Tools = append(config.ToolPolicy.Tools, rule)
		}
	}
}

func parseFailActions(json gjson.Result, config *AgentGuardConfig) {
	if v := json.Get("redis_fail_action"); v.Exists() {
		config.RedisFailAction = v.String()
	}
	if v := json.Get("security_fail_action"); v.Exists() {
		config.SecurityFailAction = v.String()
	}
}

func parseIdentityTrust(json gjson.Result, config *AgentGuardConfig) {
	it := json.Get("identity_trust")
	if !it.Exists() {
		return
	}

	if v := it.Get("mode"); v.Exists() {
		config.IdentityTrust.Mode = v.String()
	}
	if v := it.Get("hmac_secret"); v.Exists() {
		config.IdentityTrust.HmacSecret = v.String()
	}
	if v := it.Get("jwks_url"); v.Exists() {
		config.IdentityTrust.JwksUrl = v.String()
	}
	if v := it.Get("internal_cidrs"); v.Exists() {
		for _, item := range v.Array() {
			config.IdentityTrust.InternalCIDRs = append(config.IdentityTrust.InternalCIDRs, item.String())
		}
	}
}
