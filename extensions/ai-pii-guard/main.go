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
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	pluginName = "ai-pii-guard"
)

func main() {}

func init() {
	wrapper.SetCtx(
		pluginName,
		wrapper.ParseConfig(parseConfig),
		wrapper.ProcessRequestHeaders(onHttpRequestHeaders),
		wrapper.ProcessRequestBody(onHttpRequestBody),
		wrapper.ProcessResponseHeaders(onHttpResponseHeaders),
		wrapper.ProcessResponseBody(onHttpResponseBody),
	)
}

// PIIRule defines a sensitive data detection rule (IR-023 DLP: category/severity/action added)
type PIIRule struct {
	// Name is the rule name for logging
	Name string `json:"name"`
	// Pattern is the regex pattern to match sensitive data
	Pattern string `json:"pattern"`
	// Replacement is the string to replace matched content (supports $1, $2 etc.)
	Replacement string `json:"replacement"`
	// Category is the data classification: pii / secret / code (defaults to pii)
	Category string `json:"category"`
	// Severity is the classification level: low / medium / high / critical (defaults to medium)
	Severity string `json:"severity"`
	// Action on match: mask (dynamic masking) / block (deny request) / alert (report only).
	// Empty means mask (backward compatible with v1.0.0 PII-only rules).
	Action string `json:"action"`
	// compiled is the compiled regex (internal use)
	compiled *regexp.Regexp
}

// PIIGuardConfig contains configuration for sensitive data detection and protection
type PIIGuardConfig struct {
	// Rules contains detection rules
	Rules []PIIRule `json:"rules"`
	// ProtectRequest indicates whether to protect sensitive data in requests
	ProtectRequest bool `json:"protect_request"`
	// ProtectResponse indicates whether to protect sensitive data in responses
	ProtectResponse bool `json:"protect_response"`
	// LogMatches indicates whether to log matches (without actual values)
	LogMatches bool `json:"log_matches"`
	// ReportFQDN is the Console service FQDN for DLP event reporting (empty disables reporting)
	ReportFQDN string `json:"report_fqdn"`
	// ReportPort is the Console service port for DLP event reporting
	ReportPort int64 `json:"report_port"`
	// ReportToken is the X-Collector-Token header value expected by Console
	ReportToken string `json:"report_token"`
}

// piiContextKey for storing detection state across phases
const piiCtxKey = "pii_guard_matched_rules"

// DefaultPIIRules returns common PII patterns
func DefaultPIIRules() []PIIRule {
	return []PIIRule{
		{
			Name:        "email",
			Pattern:     `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			Replacement: "[EMAIL_REDACTED]",
			Category:    "pii",
			Severity:    "medium",
			Action:      "mask",
		},
		{
			Name:        "phone_cn",
			Pattern:     `\b1[3-9]\d{9}\b`,
			Replacement: "[PHONE_REDACTED]",
			Category:    "pii",
			Severity:    "medium",
			Action:      "mask",
		},
		{
			Name:        "phone_intl",
			Pattern:     `\+\d{1,3}[-.\s]?\d{1,14}`,
			Replacement: "[PHONE_REDACTED]",
			Category:    "pii",
			Severity:    "low",
			Action:      "mask",
		},
		{
			Name:        "id_card_cn",
			Pattern:     `\b\d{17}[\dXx]\b`,
			Replacement: "[ID_REDACTED]",
			Category:    "pii",
			Severity:    "high",
			Action:      "mask",
		},
		{
			Name:        "credit_card",
			Pattern:     `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
			Replacement: "[CARD_REDACTED]",
			Category:    "pii",
			Severity:    "high",
			Action:      "mask",
		},
		{
			Name:        "ssn_us",
			Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
			Replacement: "[SSN_REDACTED]",
			Category:    "pii",
			Severity:    "high",
			Action:      "mask",
		},
		{
			Name:        "ipv4",
			Pattern:     `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
			Replacement: "[IP_REDACTED]",
			Category:    "pii",
			Severity:    "low",
			Action:      "mask",
		},
	}
}

// DefaultSecretRules returns built-in secret/credential detection rules (IR-023: code/secret exfiltration)
func DefaultSecretRules() []PIIRule {
	return []PIIRule{
		{
			Name:        "aws_access_key",
			Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
			Replacement: "[SECRET_REDACTED]",
			Category:    "secret",
			Severity:    "critical",
			Action:      "block",
		},
		{
			Name:        "private_key_block",
			Pattern:     `-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`,
			Replacement: "[SECRET_REDACTED]",
			Category:    "secret",
			Severity:    "critical",
			Action:      "block",
		},
		{
			Name:        "github_token",
			Pattern:     `\bgh[pousr]_[A-Za-z0-9]{30,}\b`,
			Replacement: "[SECRET_REDACTED]",
			Category:    "secret",
			Severity:    "critical",
			Action:      "block",
		},
		{
			Name:        "openai_style_key",
			Pattern:     `\bsk-[A-Za-z0-9_-]{20,}\b`,
			Replacement: "[SECRET_REDACTED]",
			Category:    "secret",
			Severity:    "high",
			Action:      "block",
		},
		{
			Name:        "jwt_token",
			Pattern:     `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`,
			Replacement: "[SECRET_REDACTED]",
			Category:    "secret",
			Severity:    "high",
			Action:      "block",
		},
		{
			Name:        "generic_secret_assignment",
			Pattern:     `(?i)\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|passwd|password)\b["']?\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{12,}`,
			Replacement: "[SECRET_REDACTED]",
			Category:    "secret",
			Severity:    "high",
			Action:      "block",
		},
	}
}

// DefaultCodeRules returns built-in code snippet detection rules (IR-023: code exfiltration alert).
// Alert-only: corporate code going out to LLMs raises an alert without blocking the request.
func DefaultCodeRules() []PIIRule {
	return []PIIRule{
		{
			// markdown code fence or common code constructs at line start
			Pattern:     `(?m)(?:\x60{3})|(?:^\s*(?:def\s+\w+\s*\(|func\s+\w+\s*\(|class\s+\w+|import\s+[\w.]+|package\s+\w+|#include\s*[<"]))`,
			Replacement: "[CODE_REDACTED]",
			Name:        "code_snippet",
			Category:    "code",
			Severity:    "medium",
			Action:      "alert",
		},
	}
}

func ruleAction(rule PIIRule) string {
	if rule.Action == "" {
		return "mask"
	}
	return rule.Action
}

func ruleCategory(rule PIIRule) string {
	if rule.Category == "" {
		return "pii"
	}
	return rule.Category
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

func ruleSeverity(rule PIIRule) string {
	if _, ok := severityRank[rule.Severity]; !ok {
		return "medium"
	}
	return rule.Severity
}

// securityScore maps severity to risk score aligned with ai-agent-guard scoring
func securityScore(sev string) int {
	switch sev {
	case "critical":
		return 90
	case "high":
		return 80
	case "low":
		return 30
	default:
		return 60
	}
}

func parseConfig(json gjson.Result, config *PIIGuardConfig) error {
	// Set defaults
	config.ProtectRequest = true
	config.ProtectResponse = false
	config.LogMatches = true
	config.ReportPort = 80

	// Parse protect_request
	if json.Get("protect_request").Exists() {
		config.ProtectRequest = json.Get("protect_request").Bool()
	}

	// Parse protect_response
	if json.Get("protect_response").Exists() {
		config.ProtectResponse = json.Get("protect_response").Bool()
	}

	// Parse log_matches
	if json.Get("log_matches").Exists() {
		config.LogMatches = json.Get("log_matches").Bool()
	}

	// IR-023: DLP event reporting configuration (Console detect-events endpoint)
	if v := json.Get("report_fqdn"); v.Exists() {
		config.ReportFQDN = v.String()
	}
	if v := json.Get("report_port"); v.Exists() {
		config.ReportPort = v.Int()
	}
	if v := json.Get("report_token"); v.Exists() {
		config.ReportToken = v.String()
	}

	// Parse rules
	rulesJson := json.Get("rules").Array()
	if len(rulesJson) == 0 {
		// Use default rules: PII masking + secret blocking + code alerting (IR-023)
		config.Rules = DefaultPIIRules()
		config.Rules = append(config.Rules, DefaultSecretRules()...)
		config.Rules = append(config.Rules, DefaultCodeRules()...)
	} else {
		config.Rules = make([]PIIRule, 0, len(rulesJson))
		for _, ruleJson := range rulesJson {
			rule := PIIRule{
				Name:        ruleJson.Get("name").String(),
				Pattern:     ruleJson.Get("pattern").String(),
				Replacement: ruleJson.Get("replacement").String(),
				Category:    ruleJson.Get("category").String(),
				Severity:    ruleJson.Get("severity").String(),
				Action:      ruleJson.Get("action").String(),
			}
			if rule.Pattern == "" {
				continue
			}
			if rule.Replacement == "" {
				rule.Replacement = "[REDACTED]"
			}
			config.Rules = append(config.Rules, rule)
		}
	}

	// Compile patterns
	for i := range config.Rules {
		compiled, err := regexp.Compile(config.Rules[i].Pattern)
		if err != nil {
			log.Warnf("Invalid sensitive data pattern '%s' for rule '%s': %v",
				config.Rules[i].Pattern, config.Rules[i].Name, err)
			continue
		}
		config.Rules[i].compiled = compiled
	}

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config PIIGuardConfig) types.Action {
	ctx.DisableReroute()
	if config.ProtectRequest {
		proxywasm.RemoveHttpRequestHeader("content-length")
	}
	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config PIIGuardConfig, body []byte) types.Action {
	if !config.ProtectRequest {
		return types.ActionContinue
	}

	// Parse messages from request body
	messages := gjson.GetBytes(body, "messages")
	if !messages.Exists() {
		return types.ActionContinue
	}

	// Process each message
	newBody := string(body)
	changed := false
	messagesArray := messages.Array()
	var hits []PIIRule
	for i, msg := range messagesArray {
		content := msg.Get("content").String()
		if content == "" {
			continue
		}

		// Detect/mask sensitive data in content
		maskedContent, matched := processText(content, config.Rules, config.LogMatches)
		hits = append(hits, matched...)
		if maskedContent != content {
			path := "messages." + itoa(i) + ".content"
			updated, err := sjson.Set(newBody, path, maskedContent)
			if err != nil {
				log.Errorf("Failed to update message content: %v", err)
			} else {
				newBody = updated
				changed = true
			}
		}
	}

	if len(hits) > 0 {
		top := topSeverityHit(hits)
		hasBlock := false
		hasAlert := false
		for _, h := range hits {
			switch ruleAction(h) {
			case "block":
				hasBlock = true
			case "alert":
				hasAlert = true
			}
		}
		// 分类分级安全事件写入 Dynamic Metadata，供 ai-agent-guard 收集并记录审计日志
		appendSecurityEvent(SecurityEvent{
			Type:     eventTypeFor(ruleCategory(top)),
			Severity: ruleSeverity(top),
			Source:   "ai-pii-guard",
			Score:    securityScore(ruleSeverity(top)),
			Detail:   "Sensitive data detected in request: " + strings.Join(ruleNames(hits), ","),
		})
		// IR-023: 外发告警上报 Console（fire-and-forget，不阻塞主链路）
		status := "masked"
		if hasBlock {
			status = "blocked"
		} else if hasAlert {
			status = "alerted"
		}
		reportDlpEvent(ctx, config, top, status)
		if hasBlock {
			// secret 类命中即阻断（IR-023 验收口径：代码/密钥外发触发告警或阻断）
			sendDenyResponse(403, "Sensitive data (secret) detected in request; blocked by ai-pii-guard")
			return types.ActionContinue
		}
		// 上下文存储，供响应头阶段设置 x-pii-detected 头
		ctx.SetContext(piiCtxKey, ruleNames(hits))
	}

	if changed {
		if err := proxywasm.ReplaceHttpRequestBody([]byte(newBody)); err != nil {
			log.Errorf("Failed to replace request body: %v", err)
		}
	}

	return types.ActionContinue
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, config PIIGuardConfig) types.Action {
	// 从上下文读取请求阶段检测到的规则名，设置响应头供 ai-agent-guard 检测
	if matchedRules, ok := ctx.GetContext(piiCtxKey).([]string); ok && len(matchedRules) > 0 {
		_ = proxywasm.AddHttpResponseHeader("x-pii-detected", strings.Join(matchedRules, ","))
	}
	if !config.ProtectResponse {
		ctx.DontReadResponseBody()
	}
	return types.ActionContinue
}

func onHttpResponseBody(ctx wrapper.HttpContext, config PIIGuardConfig, body []byte) types.Action {
	if !config.ProtectResponse {
		return types.ActionContinue
	}

	// Parse response content
	choices := gjson.GetBytes(body, "choices")
	if !choices.Exists() {
		return types.ActionContinue
	}

	newBody := string(body)
	for i, choice := range choices.Array() {
		content := choice.Get("message.content").String()
		if content == "" {
			continue
		}

		// Mask PII in content
		maskedContent, _ := maskPII(content, config.Rules, config.LogMatches)
		if maskedContent != content {
			path := "choices." + itoa(i) + ".message.content"
			var err error
			newBody, err = sjson.Set(newBody, path, maskedContent)
			if err != nil {
				log.Errorf("Failed to update response content: %v", err)
			}
		}
	}

	if newBody != string(body) {
		if err := proxywasm.ReplaceHttpResponseBody([]byte(newBody)); err != nil {
			log.Errorf("Failed to replace response body: %v", err)
		}
	}

	return types.ActionContinue
}

// processText applies rules to the given text.
// mask rules replace matched content; block/alert rules only record hits.
// 返回处理后的文本和命中的规则列表（含分类分级元数据）
func processText(text string, rules []PIIRule, logMatches bool) (string, []PIIRule) {
	result := text
	var hits []PIIRule
	for _, rule := range rules {
		if rule.compiled == nil {
			continue
		}
		if rule.compiled.MatchString(result) {
			if logMatches {
				log.Infof("Sensitive data detected: rule=%s category=%s severity=%s action=%s",
					rule.Name, ruleCategory(rule), ruleSeverity(rule), ruleAction(rule))
			}
			hits = append(hits, rule)
			if ruleAction(rule) == "mask" {
				result = rule.compiled.ReplaceAllString(result, rule.Replacement)
			}
		}
	}
	return result, hits
}

// maskPII masks sensitive data in the given text using the configured rules
// 返回脱敏后的文本和命中的规则名列表
func maskPII(text string, rules []PIIRule, logMatches bool) (string, []string) {
	result, hits := processText(text, rules, logMatches)
	return result, ruleNames(hits)
}

// MaskPIIInMessages masks PII in messages (exported for testing)
func MaskPIIInMessages(messages string, rules []PIIRule) string {
	masked, _ := maskPII(messages, rules, false)
	return masked
}

func ruleNames(rules []PIIRule) []string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.Name)
	}
	return names
}

// topSeverityHit returns the hit with the highest classification severity
func topSeverityHit(hits []PIIRule) PIIRule {
	top := hits[0]
	for _, h := range hits[1:] {
		if severityRank[ruleSeverity(h)] > severityRank[ruleSeverity(top)] {
			top = h
		}
	}
	return top
}

// eventTypeFor maps data category to security event type
func eventTypeFor(category string) string {
	switch category {
	case "secret":
		return "secret_exfil"
	case "code":
		return "code_exfil"
	default:
		return "pii_leak"
	}
}

// reportDlpEvent reports a DLP event to Console detect-events endpoint
// （上报模式与 key-auth sai-b15 对齐：FQDNCluster + X-Collector-Token，fire-and-forget）
func reportDlpEvent(ctx wrapper.HttpContext, config PIIGuardConfig, top PIIRule, status string) {
	if config.ReportFQDN == "" {
		return
	}
	host, err := proxywasm.GetHttpRequestHeader(":authority")
	if err != nil || host == "" {
		host, _ = proxywasm.GetHttpRequestHeader("host")
	}
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	if host == "" {
		host = "unknown"
	}
	srcIp, _ := proxywasm.GetHttpRequestHeader("x-forwarded-for")
	if srcIp == "" {
		srcIp = "unknown"
	}
	detail, _ := json.Marshal(map[string]interface{}{
		"reason": "sensitive data " + status + " by ai-pii-guard",
		"rule":   top.Name,
		"route":  host,
		"action": status,
	})
	body, _ := json.Marshal(map[string]interface{}{
		"events": []map[string]interface{}{{
			"detectType": "dlp_leak",
			"domain":     host,
			"category":   ruleCategory(top),
			"riskLevel":  ruleSeverity(top),
			"status":     status,
			"source":     "gateway",
			"srcIp":      srcIp,
			"detail":     string(detail),
			"eventTime":  time.Now().UnixMilli(),
		}},
	})
	headers := [][2]string{
		{"Content-Type", "application/json"},
	}
	if config.ReportToken != "" {
		headers = append(headers, [2]string{"X-Collector-Token", config.ReportToken})
	}
	client := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: config.ReportFQDN, Port: config.ReportPort})
	dispatchErr := client.Post("/v1/shadow-ai/detect-events", headers, body,
		func(statusCode int, responseHeaders http.Header, responseBody []byte) {
			if statusCode != 200 {
				log.Errorf("dlp event report failed: status=%d body=%s", statusCode, string(responseBody))
			} else {
				log.Infof("dlp event reported: rule=%s status=%s domain=%s", top.Name, status, host)
			}
		}, 1500)
	if dispatchErr != nil {
		log.Errorf("dlp event report dispatch error: %v", dispatchErr)
	}
}

// sendDenyResponse sends an OpenAI-compatible block response (pattern aligned with ai-prompt-guard)
func sendDenyResponse(statusCode uint32, message string) {
	errorResponse := `{"error":{"message":"` + message + `","type":"pii_guard_error","code":"sensitive_data_blocked"}}`
	headers := [][2]string{
		{"content-type", "application/json"},
	}
	proxywasm.SendHttpResponse(statusCode, headers, []byte(errorResponse), -1)
}

// SecurityEvent 安全事件（与 ai-agent-guard 的 SecurityEvent 结构对齐）
type SecurityEvent struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Score    int    `json:"score"`
	Detail   string `json:"detail"`
}

// appendSecurityEvent 向 Dynamic Metadata 追加安全事件，供 ai-agent-guard 收集并记录审计日志
func appendSecurityEvent(event SecurityEvent) {
	var events []SecurityEvent
	if existing, err := proxywasm.GetProperty([]string{"security_events", "events"}); err == nil && len(existing) > 0 {
		_ = json.Unmarshal(existing, &events)
	}
	events = append(events, event)
	data, err := json.Marshal(events)
	if err != nil {
		log.Warnf("marshal security events failed: %v", err)
		return
	}
	if err := proxywasm.SetProperty([]string{"security_events", "events"}, data); err != nil {
		log.Warnf("set security_events metadata failed: %v", err)
	}
}

// itoa converts int to string without importing strconv
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var result strings.Builder
	negative := i < 0
	if negative {
		i = -i
	}
	for i > 0 {
		result.WriteByte(byte('0' + i%10))
		i /= 10
	}
	// Reverse
	s := result.String()
	reversed := make([]byte, len(s))
	for j := 0; j < len(s); j++ {
		reversed[j] = s[len(s)-1-j]
	}
	if negative {
		return "-" + string(reversed)
	}
	return string(reversed)
}
