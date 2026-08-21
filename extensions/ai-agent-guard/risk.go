package main

import (
	"ai-agent-guard/config"

	"github.com/higress-group/wasm-go/pkg/log"
)

// calculateRiskIncrement 根据安全事件计算风险增量
func calculateRiskIncrement(cfg *config.AgentGuardConfig, events []SecurityEvent, rs *RequestState) int {
	totalIncrement := 0

	for _, event := range events {
		// 优先使用事件自带的 Score
		increment := event.Score

		// 如果事件未携带 Score，从配置的基础权重中查找
		if increment == 0 {
			if weight, ok := cfg.RiskScoring.BaseWeights[event.Type]; ok {
				increment = weight
			}
		}

		// 根据严重程度调整
		switch event.Severity {
		case "high":
			increment = increment * 2
		case "medium":
			// 保持原值
		case "low":
			increment = increment / 2
		}

		totalIncrement += increment
		log.Debugf("risk event: type=%s severity=%s score=%d increment=%d",
			event.Type, event.Severity, event.Score, increment)
	}

	// 工具调用风险增量
	if rs.ToolName != "" {
		for _, rule := range cfg.ToolPolicy.Tools {
			if rule.Name == rs.ToolName && rule.HighRisk {
				totalIncrement += rule.RiskDeltaOnCall
				log.Debugf("high-risk tool call: tool=%s delta=%d", rs.ToolName, rule.RiskDeltaOnCall)
				break
			}
		}
	}

	return totalIncrement
}

// detectBehaviorRisk 行为风险实时检测（纯内存计算，无 Redis 交互，无时区依赖，不阻断）
//
// 设计约束（方案 4.4）：
//   - Wasm 端只计算 BehaviorRiskScore 并随 AuditLogEntry 写入现有审计日志
//   - 不启动 Goroutine、不写告警 Redis、不做首次使用检测的 Redis 调用
//   - 告警由后端 runRiskDetection() 扫描高 behavior_risk_score 的审计日志时统一生成
func detectBehaviorRisk(cfg *config.AgentGuardConfig, rs *RequestState) int {
	score := 0

	// 1. 身份错配：guest 用户 + 高风险 Agent（仅当身份可信时才计分）
	if rs.IdentityTrusted && rs.UserRole == "guest" &&
		rs.SessionMeta != nil && rs.SessionMeta.RiskScore >= 70 {
		score += 30
	}

	// 2. 链路异常：轮次突增（阈值法，首次使用检测由后端画像比对完成）
	if rs.SessionMeta != nil && rs.SessionMeta.StepCount > 20 {
		score += 20
	}

	// 3. 策略异常：安全事件命中后仍继续（仅当 action 非合规降级时，详见 7.5）
	if len(rs.Events) > 0 && !rs.Blocked && !isCompliantDegrade(cfg, rs) {
		score += 25
	}

	return score
}

// isCompliantDegrade 判断当前请求是否为合规的 WARN 降级
//
// 合规降级：安全事件命中但按配置采取 alert/enhance（非 block）响应，
// 属于预期的降级策略，不计策略异常分（方案 7.5）。
// 当 action 为空（事件未达阈值）或 block（已拦截）时，均非合规降级。
func isCompliantDegrade(cfg *config.AgentGuardConfig, rs *RequestState) bool {
	if rs.SessionMeta == nil {
		return false
	}
	action := determineAction(&cfg.RiskScoring, rs.SessionMeta.RiskScore)
	// action 为配置的 WARN 级别（非空且非 Critical/block）即为合规降级
	return action != "" && action != cfg.RiskScoring.Actions.Critical
}
