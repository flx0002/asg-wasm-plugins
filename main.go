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
	"regexp"
	"strings"

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

// PIIRule defines a PII detection rule
type PIIRule struct {
	// Name is the rule name for logging
	Name string `json:"name"`
	// Pattern is the regex pattern to match PII
	Pattern string `json:"pattern"`
	// Replacement is the string to replace matched PII (supports $1, $2 etc.)
	Replacement string `json:"replacement"`
	// compiled is the compiled regex (internal use)
	compiled *regexp.Regexp
}

// PIIGuardConfig contains configuration for PII detection and protection
type PIIGuardConfig struct {
	// Rules contains PII detection rules
	Rules []PIIRule `json:"rules"`
	// ProtectRequest indicates whether to protect PII in requests
	ProtectRequest bool `json:"protect_request"`
	// ProtectResponse indicates whether to protect PII in responses
	ProtectResponse bool `json:"protect_response"`
	// LogMatches indicates whether to log PII matches (without actual values)
	LogMatches bool `json:"log_matches"`
}

// piiContextKey for storing PII detection state across phases
const piiCtxKey = "pii_guard_matched_rules"

// DefaultPIIRules returns common PII patterns
func DefaultPIIRules() []PIIRule {
	return []PIIRule{
		{
			Name:        "email",
			Pattern:     `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			Replacement: "[EMAIL_REDACTED]",
		},
		{
			Name:        "phone_cn",
			Pattern:     `\b1[3-9]\d{9}\b`,
			Replacement: "[PHONE_REDACTED]",
		},
		{
			Name:        "phone_intl",
			Pattern:     `\+\d{1,3}[-.\s]?\d{1,14}`,
			Replacement: "[PHONE_REDACTED]",
		},
		{
			Name:        "id_card_cn",
			Pattern:     `\b\d{17}[\dXx]\b`,
			Replacement: "[ID_REDACTED]",
		},
		{
			Name:        "credit_card",
			Pattern:     `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
			Replacement: "[CARD_REDACTED]",
		},
		{
			Name:        "ssn_us",
			Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
			Replacement: "[SSN_REDACTED]",
		},
		{
			Name:        "ipv4",
			Pattern:     `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
			Replacement: "[IP_REDACTED]",
		},
	}
}

func parseConfig(json gjson.Result, config *PIIGuardConfig) error {
	// Set defaults
	config.ProtectRequest = true
	config.ProtectResponse = false
	config.LogMatches = true

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

	// Parse rules
	rulesJson := json.Get("rules").Array()
	if len(rulesJson) == 0 {
		// Use default rules
		config.Rules = DefaultPIIRules()
	} else {
		config.Rules = make([]PIIRule, 0, len(rulesJson))
		for _, ruleJson := range rulesJson {
			rule := PIIRule{
				Name:        ruleJson.Get("name").String(),
				Pattern:     ruleJson.Get("pattern").String(),
				Replacement: ruleJson.Get("replacement").String(),
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
			log.Warnf("Invalid PII pattern '%s' for rule '%s': %v",
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
	messagesArray := messages.Array()
	var matchedRules []string
	for i, msg := range messagesArray {
		content := msg.Get("content").String()
		if content == "" {
			continue
		}

		// Mask PII in content
		maskedContent, matched := maskPII(content, config.Rules, config.LogMatches)
		if len(matched) > 0 {
			matchedRules = append(matchedRules, matched...)
		}
		if maskedContent != content {
			path := "messages." + itoa(i) + ".content"
			var err error
			newBody, err = sjson.Set(newBody, path, maskedContent)
			if err != nil {
				log.Errorf("Failed to update message content: %v", err)
			}
		}
	}

	// 检测到 PII 时写入安全事件到 Dynamic Metadata，供 ai-agent-guard 收集并记录审计日志
	if len(matchedRules) > 0 {
		// 方案 A：Dynamic Metadata（同 VM 内共享）
		appendSecurityEvent(SecurityEvent{
			Type:     "pii_leak",
			Severity: "medium",
			Source:   "ai-pii-guard",
			Score:    60,
			Detail:   "PII detected and masked in request: " + strings.Join(matchedRules, ","),
		})
		// 方案 B：上下文存储，供响应头阶段设置 x-pii-detected 头（跨 VM 保底方案）
		ctx.SetContext(piiCtxKey, matchedRules)
	}

	if newBody != string(body) {
		if err := proxywasm.ReplaceHttpRequestBody([]byte(newBody)); err != nil {
			log.Errorf("Failed to replace request body: %v", err)
		}
	}

	return types.ActionContinue
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, config PIIGuardConfig) types.Action {
	// 从上下文读取请求阶段检测到的 PII 规则名，设置响应头供 ai-agent-guard 检测
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

// maskPII masks PII in the given text using the configured rules
// 返回脱敏后的文本和命中的规则名列表
func maskPII(text string, rules []PIIRule, logMatches bool) (string, []string) {
	result := text
	var matched []string
	for _, rule := range rules {
		if rule.compiled == nil {
			continue
		}
		if rule.compiled.MatchString(result) {
			if logMatches {
				log.Infof("PII detected: rule=%s", rule.Name)
			}
			matched = append(matched, rule.Name)
			result = rule.compiled.ReplaceAllString(result, rule.Replacement)
		}
	}
	return result, matched
}

// MaskPIIInMessages masks PII in messages (exported for testing)
func MaskPIIInMessages(messages string, rules []PIIRule) string {
	masked, _ := maskPII(messages, rules, false)
	return masked
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
