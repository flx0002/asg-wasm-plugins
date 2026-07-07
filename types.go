package main

// RequestState 单次请求的上下文状态，在请求生命周期内通过 HttpContext 传递
type RequestState struct {
	// Session 关联
	SessionID string
	Mode      string // full | degraded

	// Agent 执行链信息（从上行 Header 提取）
	StepIndex      string
	StepType       string
	ToolName       string
	ToolParamsHash string
	ParentStep     string

	// 安全事件收集
	EventKey string
	Events   []SecurityEvent

	// 风险评分
	RiskIncrement int

	// Session 元数据（从 Redis 读取）
	SessionMeta *SessionMeta

	// Token 用量
	InputToken  int64
	OutputToken int64

	// 请求/响应体大小
	RequestBodySize  int64
	ResponseBodySize int64

	// 模型名
	Model string

	// 标记
	ResponseCaptured bool
	AuditWritten     bool // 审计日志是否已写入，防止多路径重复写入

	// 拦截状态（全链路审计）
	Blocked        bool
	ResponseStatus int
	Sequence       int64 // 请求序列号，用于 Score 防乱序

	// === 行为分析：身份与行为字段 ===
	IdentityTrusted   bool   // 身份是否通过信任校验
	UserID            string // 用户标识（信任校验后取值）
	UserName          string // 用户名
	UserDept          string // 部门
	UserRole          string // 角色
	AgentID           string // 智能体标识
	AgentOwner        string // 智能体归属人
	AgentType         string // 智能体类型（chat/code/agent）
	SourceIP          string // 来源 IP
	UserAgent         string // 客户端标识
	TraceID           string // W3C Trace ID
	ToolCallID        string // 工具调用 ID
	RetrievalID       string // RAG 检索 ID
	KnowledgeBaseID   string // 知识库 ID
	ResponseStartTime int64  // 响应开始时间（UnixMilli），用于计算延迟
	BehaviorRiskScore int    // 行为风险分（Wasm 标记，后端据此生成告警）
}

// SessionMeta Session 级状态数据（存储在 Redis Hash 中）
type SessionMeta struct {
	RiskScore      int   `json:"risk_score"`
	RequestCount   int   `json:"request_count"`
	StepCount      int   `json:"step_count"`
	TokenCount     int64 `json:"token_count"`
	ViolationCount int   `json:"violation_count"`
	LastActiveTime int64 `json:"last_active_time"` // Unix 时间戳（秒）
	CreatedAt      int64 `json:"created_at"`       // Unix 时间戳（秒）
}

// SecurityEvent 安全事件（由安全插件通过 Dynamic Metadata 或 Redis 写入）
type SecurityEvent struct {
	Type       string `json:"type"`        // 事件类型：prompt_injection, content_violation, pii_leak 等
	Severity   string `json:"severity"`    // 严重程度：low, medium, high
	Source     string `json:"source"`      // 事件来源插件：ai-prompt-guard, ai-content-safety 等
	Score      int    `json:"score"`       // 事件风险分值
	Detail     string `json:"detail"`      // 事件详情（已脱敏）
	ToolName   string `json:"tool_name"`   // 相关工具名（可选）
}
