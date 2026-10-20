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
)

const (
	pluginName = "ai-prompt-guard"
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

// RuleItem is a named detection rule written by the console page schema
// (denyRules/allowRules), kept compatible with legacy deny_patterns/allow_patterns.
type RuleItem struct {
	Name      string `json:"name"`
	Regex     string `json:"regex"`
	MatchType string `json:"matchType"` // "regex" (default) or "contains"
}

// KeywordRuleGroup is a content-compliance rule group aligned with
// GB/T 45654-2025 Appendix A risk categories (name carries the standard code).
type KeywordRuleGroup struct {
	Name     string   `json:"name"`
	Keywords []string `json:"keywords"`
	Patterns []string `json:"patterns"`
	Enabled  *bool    `json:"enabled"` // nil defaults to true
}

// AdvisoryRule carries a non-blocking safety note injected into responses
// when a high-stakes service scenario is hit (GB/T 45654 Appendix A.5).
type AdvisoryRule struct {
	Name     string   `json:"name"`
	Keywords []string `json:"keywords"`
	Advice   string   `json:"advice"`
	Enabled  *bool    `json:"enabled"`
}

// PromptGuardConfig contains configuration for malicious prompt detection
type PromptGuardConfig struct {
	// DenyPatterns contains regex patterns to block malicious prompts (legacy schema)
	DenyPatterns []string `json:"deny_patterns"`
	// AllowPatterns contains regex patterns to explicitly allow (bypass deny) (legacy schema)
	AllowPatterns []string `json:"allow_patterns"`
	// DenyRules / AllowRules are the console page schema rules (v1.0.4+)
	DenyRules  []RuleItem `json:"denyRules"`
	AllowRules []RuleItem `json:"allowRules"`
	// KeywordRules are grouped content-compliance keyword libraries (GB/T 45654 App. A)
	KeywordRules []KeywordRuleGroup `json:"keywordRules"`
	// AdvisoryRules append a safety note to responses instead of blocking (A.5)
	AdvisoryRules []AdvisoryRule `json:"advisoryRules"`
	// DetectMode: "deny" (default) blocks on hit; "monitor" only logs an event and passes.
	// parseConfig normalizes block/deny->deny and detect/monitor/observe/pass/dry_run->monitor,
	// and honors a `mode` alias key, so the on-hit action stays a single unambiguous concept.
	DetectMode string `json:"detectMode"`
	// RejectMessage is the page-schema alias of deny_message
	RejectMessage string `json:"rejectMessage"`
	// CheckRequest enables input-side detection (default true)
	CheckRequest bool `json:"checkRequest"`
	// CheckResponse enables output-side detection (default false)
	CheckResponse bool `json:"checkResponse"`
	// DenyCode is the HTTP status code to return when blocked
	DenyCode int `json:"deny_code"`
	// DenyMessage is the message to return when blocked
	DenyMessage string `json:"deny_message"`
	// CaseSensitive indicates whether pattern matching is case-sensitive
	CaseSensitive bool `json:"case_sensitive"`
	// EnableNormalization enables decoding (rot13/base64/unicode/url/hex) before deny matching
	EnableNormalization bool `json:"enable_normalization"`
	// MaxDecodeCandidates limits the number of decode candidates
	MaxDecodeCandidates int `json:"max_decode_candidates"`

	// Compiled patterns (internal use)
	compiledDenyPatterns  []*compiledRule
	compiledAllowPatterns []*compiledRule
	compiledKeywordGroups []compiledKeywordGroup
	compiledAdvisory      []compiledAdvisory
}

// compiledRule pairs a regex with its optional rule name for event detail.
type compiledRule struct {
	name string
	re   *regexp.Regexp
}

// compiledKeywordGroup holds lower-cased keywords plus compiled variants for one risk group.
type compiledKeywordGroup struct {
	name     string
	keywords []string
	patterns []*regexp.Regexp
}

type compiledAdvisory struct {
	name     string
	keywords []string
	advice   string
}

func compileRuleItem(item RuleItem, caseSensitive bool) (*compiledRule, error) {
	pattern := item.Regex
	if item.MatchType == "contains" {
		pattern = regexp.QuoteMeta(item.Regex)
	}
	if !caseSensitive && !strings.HasPrefix(pattern, "(?i)") {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &compiledRule{name: item.Name, re: re}, nil
}

func parseConfig(json gjson.Result, config *PromptGuardConfig) error {
	// Set defaults
	config.DenyCode = 403
	config.DenyMessage = "Request blocked by prompt guard"
	config.CaseSensitive = false
	config.EnableNormalization = true
	config.MaxDecodeCandidates = defaultMaxCandidates
	config.CheckRequest = true
	config.DetectMode = "deny"

	if json.Get("enable_normalization").Exists() {
		config.EnableNormalization = json.Get("enable_normalization").Bool()
	}
	if json.Get("max_decode_candidates").Exists() {
		config.MaxDecodeCandidates = int(json.Get("max_decode_candidates").Int())
	}
	if json.Get("deny_code").Exists() {
		config.DenyCode = int(json.Get("deny_code").Int())
	}
	if json.Get("deny_message").Exists() {
		config.DenyMessage = json.Get("deny_message").String()
	}
	if json.Get("rejectMessage").Exists() {
		config.RejectMessage = json.Get("rejectMessage").String()
	}
	if config.RejectMessage != "" {
		config.DenyMessage = config.RejectMessage
	}
	if json.Get("case_sensitive").Exists() {
		config.CaseSensitive = json.Get("case_sensitive").Bool()
	}
	// detectMode canonical values: "deny" = block on hit, "monitor" = record event and pass.
	// Normalize naming aliases and accept the `mode` alias key so the single on-hit-action
	// concept stays unambiguous no matter which spelling the console page writes:
	//   block/deny -> deny ; detect/monitor/observe/pass/dry_run -> monitor
	rawMode := ""
	if json.Get("detectMode").Exists() {
		rawMode = json.Get("detectMode").String()
	} else if json.Get("mode").Exists() {
		rawMode = json.Get("mode").String()
	}
	if rawMode != "" {
		switch strings.ToLower(rawMode) {
		case "deny", "block":
			config.DetectMode = "deny"
		case "monitor", "detect", "observe", "pass", "dry_run", "dryrun":
			config.DetectMode = "monitor"
		default:
			log.Warnf("unknown detectMode %q, fallback to deny", rawMode)
			config.DetectMode = "deny"
		}
	}
	if json.Get("checkRequest").Exists() {
		config.CheckRequest = json.Get("checkRequest").Bool()
	}
	if json.Get("checkResponse").Exists() {
		config.CheckResponse = json.Get("checkResponse").Bool()
	}

	// Parse legacy deny_patterns
	denyPatterns := json.Get("deny_patterns").Array()
	config.DenyPatterns = make([]string, 0, len(denyPatterns))
	for _, pattern := range denyPatterns {
		patternStr := pattern.String()
		config.DenyPatterns = append(config.DenyPatterns, patternStr)
		rule, err := compileRuleItem(RuleItem{Regex: patternStr, MatchType: "regex"}, config.CaseSensitive)
		if err != nil {
			log.Warnf("Invalid deny pattern '%s': %v", patternStr, err)
			continue
		}
		config.compiledDenyPatterns = append(config.compiledDenyPatterns, rule)
	}

	// Parse page-schema denyRules
	for _, raw := range json.Get("denyRules").Array() {
		item := RuleItem{Name: raw.Get("name").String(), Regex: raw.Get("regex").String(), MatchType: raw.Get("matchType").String()}
		if item.Regex == "" {
			continue
		}
		rule, err := compileRuleItem(item, config.CaseSensitive)
		if err != nil {
			log.Warnf("Invalid denyRule '%s': %v", item.Name, err)
			continue
		}
		config.compiledDenyPatterns = append(config.compiledDenyPatterns, rule)
	}

	// Parse legacy allow_patterns
	allowPatterns := json.Get("allow_patterns").Array()
	config.AllowPatterns = make([]string, 0, len(allowPatterns))
	for _, pattern := range allowPatterns {
		patternStr := pattern.String()
		config.AllowPatterns = append(config.AllowPatterns, patternStr)
		rule, err := compileRuleItem(RuleItem{Regex: patternStr, MatchType: "regex"}, config.CaseSensitive)
		if err != nil {
			log.Warnf("Invalid allow pattern '%s': %v", patternStr, err)
			continue
		}
		config.compiledAllowPatterns = append(config.compiledAllowPatterns, rule)
	}

	// Parse page-schema allowRules
	for _, raw := range json.Get("allowRules").Array() {
		item := RuleItem{Name: raw.Get("name").String(), Regex: raw.Get("regex").String(), MatchType: raw.Get("matchType").String()}
		if item.Regex == "" {
			continue
		}
		rule, err := compileRuleItem(item, config.CaseSensitive)
		if err != nil {
			log.Warnf("Invalid allowRule '%s': %v", item.Name, err)
			continue
		}
		config.compiledAllowPatterns = append(config.compiledAllowPatterns, rule)
	}

	// Parse keywordRules groups
	for _, raw := range json.Get("keywordRules").Array() {
		group := KeywordRuleGroup{Name: raw.Get("name").String()}
		if raw.Get("enabled").Exists() {
			enabled := raw.Get("enabled").Bool()
			group.Enabled = &enabled
		}
		if group.Enabled != nil && !*group.Enabled {
			continue
		}
		for _, kw := range raw.Get("keywords").Array() {
			k := strings.ToLower(kw.String())
			if k != "" {
				group.Keywords = append(group.Keywords, k)
			}
		}
		cg := compiledKeywordGroup{name: group.Name, keywords: group.Keywords}
		for _, p := range raw.Get("patterns").Array() {
			pattern := p.String()
			if pattern == "" {
				continue
			}
			if !config.CaseSensitive && !strings.HasPrefix(pattern, "(?i)") {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Warnf("Invalid keyword rule pattern in '%s': %v", group.Name, err)
				continue
			}
			cg.patterns = append(cg.patterns, re)
		}
		if len(cg.keywords) == 0 && len(cg.patterns) == 0 {
			continue
		}
		config.compiledKeywordGroups = append(config.compiledKeywordGroups, cg)
	}

	// Parse advisoryRules
	for _, raw := range json.Get("advisoryRules").Array() {
		if raw.Get("enabled").Exists() && !raw.Get("enabled").Bool() {
			continue
		}
		adv := compiledAdvisory{name: raw.Get("name").String(), advice: raw.Get("advice").String()}
		for _, kw := range raw.Get("keywords").Array() {
			k := strings.ToLower(kw.String())
			if k != "" {
				adv.keywords = append(adv.keywords, k)
			}
		}
		if len(adv.keywords) == 0 || adv.advice == "" {
			continue
		}
		config.compiledAdvisory = append(config.compiledAdvisory, adv)
	}

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config PromptGuardConfig) types.Action {
	ctx.DisableReroute()
	proxywasm.RemoveHttpRequestHeader("content-length")
	return types.ActionContinue
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, config PromptGuardConfig) types.Action {
	if !config.CheckResponse {
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}
	ct, _ := proxywasm.GetHttpResponseHeader("content-type")
	if strings.Contains(ct, "text/event-stream") {
		// Streaming (SSE) responses are not buffered; known limitation.
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}
	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config PromptGuardConfig, body []byte) types.Action {
	if !config.CheckRequest {
		return types.ActionContinue
	}
	// Extract messages from request body
	messages := gjson.GetBytes(body, "messages")
	if !messages.Exists() {
		log.Debugf("No messages field found in request body")
		return types.ActionContinue
	}

	for _, msg := range messages.Array() {
		content := msg.Get("content").String()
		if content == "" {
			continue
		}
		hit, info := detectContent(content, config)
		if hit {
			if config.DetectMode == "monitor" {
				log.Infof("Malicious prompt detected (group=%s method=%s) in monitor mode, request passed", info.group, info.method)
				appendSecurityEvent(eventFor(info, "request"))
				continue
			}
			log.Infof("Malicious prompt detected (group=%s method=%s), blocking request", info.group, info.method)
			appendSecurityEvent(eventFor(info, "request"))
			sendDenyResponse(config.DenyCode, config.DenyMessage)
			return types.ActionContinue
		}
	}

	return types.ActionContinue
}

type hitInfo struct {
	group  string
	detail string
	method string // "plain", decode method, or "keyword"
	kind   string // "prompt_injection" or "content_violation"
}

// detectContent checks text against allow (bypass), deny patterns/rules,
// keyword groups and advisory groups. Advisory hits are not blocking here.
func detectContent(text string, config PromptGuardConfig) (bool, hitInfo) {
	if matchesAnyCompiledRule(text, config.compiledAllowPatterns) {
		log.Debugf("Content matches allow rule, bypassing deny check")
		return false, hitInfo{}
	}
	// deny rules: plain regex first, then decoded variants
	for _, rule := range config.compiledDenyPatterns {
		if rule.re.MatchString(text) {
			name := rule.name
			if name == "" {
				name = "deny_pattern"
			}
			return true, hitInfo{group: name, detail: "Detected prompt injection / jailbreak pattern: " + name, method: "plain", kind: "prompt_injection"}
		}
	}
	if config.EnableNormalization {
		for _, c := range NormalizeForDetection(text, config.MaxDecodeCandidates) {
			if c.Method == "original" {
				continue
			}
			for _, rule := range config.compiledDenyPatterns {
				if rule.re.MatchString(c.Text) {
					name := rule.name
					if name == "" {
						name = "deny_pattern"
					}
					return true, hitInfo{group: name, detail: "Detected prompt injection / jailbreak pattern: " + name + " (decoded via " + c.Method + ")", method: c.Method, kind: "prompt_injection"}
				}
			}
		}
	}
	// keyword groups (GB/T 45654 Appendix A risk library)
	lower := strings.ToLower(text)
	for _, g := range config.compiledKeywordGroups {
		for _, kw := range g.keywords {
			if strings.Contains(lower, kw) {
				return true, hitInfo{group: g.name, detail: "GB/T 45654 Appendix A risk hit [" + g.name + "] keyword: " + kw, method: "keyword", kind: "content_violation"}
			}
		}
		for _, re := range g.patterns {
			if re.MatchString(text) {
				return true, hitInfo{group: g.name, detail: "GB/T 45654 Appendix A risk hit [" + g.name + "] variant pattern", method: "regex", kind: "content_violation"}
			}
		}
	}
	return false, hitInfo{}
}

func eventFor(info hitInfo, direction string) SecurityEvent {
	severity := "high"
	score := 80
	if info.kind == "content_violation" {
		severity = "high"
		score = 90
	}
	return SecurityEvent{
		Type:      info.kind,
		Severity:  severity,
		Source:    pluginName,
		Score:     score,
		Detail:    info.detail,
		Direction: direction,
	}
}

func onHttpResponseBody(ctx wrapper.HttpContext, config PromptGuardConfig, body []byte) types.Action {
	if !config.CheckResponse {
		return types.ActionContinue
	}
	text := extractResponseText(body)
	if strings.HasPrefix(strings.TrimSpace(string(body)), "data:") {
		// SSE frames slipping past header check: pass through unbuffered decision
		log.Debugf("SSE response body detected, skipping output-side check")
		return types.ActionContinue
	}
	if text == "" {
		return types.ActionContinue
	}

	hit, info := detectContent(text, config)
	if hit {
		if config.DetectMode == "monitor" {
			log.Infof("Violation detected in model output (group=%s) in monitor mode, response passed", info.group)
			appendSecurityEvent(eventFor(info, "response"))
			return types.ActionContinue
		}
		log.Infof("Violation detected in model output (group=%s method=%s), blocking response", info.group, info.method)
		appendSecurityEvent(eventFor(info, "response"))
		sendDenyResponse(config.DenyCode, config.DenyMessage)
		return types.ActionContinue
	}

	// Advisory injection (A.5): append safety note without blocking
	for _, adv := range config.compiledAdvisory {
		lower := strings.ToLower(text)
		for _, kw := range adv.keywords {
			if strings.Contains(lower, kw) {
				advised := appendAdvice(body, adv.advice)
				if advised != nil {
					log.Infof("Advisory rule [%s] applied to response", adv.name)
					if err := proxywasm.ReplaceHttpResponseBody(advised); err != nil {
						log.Warnf("replace response body failed: %v", err)
					}
				}
				return types.ActionContinue
			}
		}
	}
	return types.ActionContinue
}

// extractResponseText pulls assistant text out of an OpenAI-style completion
// response (or the raw text for non-JSON bodies).
func extractResponseText(body []byte) string {
	if !gjson.ValidBytes(body) {
		return string(body)
	}
	var sb strings.Builder
	choices := gjson.GetBytes(body, "choices")
	if choices.Exists() {
		for _, c := range choices.Array() {
			sb.WriteString(c.Get("message.content").String())
		}
	}
	if sb.Len() == 0 {
		sb.WriteString(gjson.GetBytes(body, "text").String())
	}
	return sb.String()
}

// appendAdvice rebuilds the response body with a safety note appended to the
// first choice message content. Returns nil when the structure is not recognized
// or when the content value appears more than once (ambiguous splice).
func appendAdvice(body []byte, advice string) []byte {
	path := "choices.0.message.content"
	if !gjson.GetBytes(body, path).Exists() {
		return nil
	}
	// gjson cannot mutate; do a lightweight replacement of the content string.
	original := gjson.GetBytes(body, path).String()
	note := "\n\n【安全提示】" + advice
	// Use encoding/json for correct escaping of the merged content.
	merged, err := json.Marshal(original + note)
	if err != nil {
		return nil
	}
	// merged already carries surrounding quotes, matching jsonQuote's format
	idx := strings.Index(string(body), jsonQuote(original))
	if idx < 0 || strings.Contains(string(body)[idx+len(jsonQuote(original)):], jsonQuote(original)) {
		return nil
	}
	out := make([]byte, 0, len(body)+len(note)+16)
	out = append(out, body[:idx]...)
	out = append(out, merged...)
	rest := body[idx+len(jsonQuote(original)):]
	out = append(out, rest...)
	return out
}

func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(b)
}

// matchesAnyCompiledRule checks if text matches any of the compiled rules
func matchesAnyCompiledRule(text string, rules []*compiledRule) bool {
	for _, rule := range rules {
		if rule.re.MatchString(text) {
			return true
		}
	}
	return false
}

// matchesAnyPattern checks if text matches any of the compiled patterns (kept for tests)
func matchesAnyPattern(text string, patterns []*regexp.Regexp) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// sendDenyResponse sends a deny response with the specified code and message
func sendDenyResponse(code int, message string) {
	var statusCode uint32 = uint32(code)

	// Build OpenAI-compatible error response
	errorResponse := buildErrorResponse(message)

	headers := [][2]string{
		{"content-type", "application/json"},
	}

	proxywasm.SendHttpResponse(statusCode, headers, []byte(errorResponse), -1)
}

// buildErrorResponse builds an OpenAI-compatible error response
func buildErrorResponse(message string) string {
	// Escape special characters for JSON
	escapedMessage := strings.ReplaceAll(message, "\"", "\\\"")
	escapedMessage = strings.ReplaceAll(escapedMessage, "\n", "\\n")

	return `{"error":{"message":"` + escapedMessage + `","type":"prompt_guard_error","code":"content_blocked"}}`
}

// SecurityEvent 安全事件（与 ai-agent-guard 的 SecurityEvent 结构对齐）
type SecurityEvent struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Source    string `json:"source"`
	Score     int    `json:"score"`
	Detail    string `json:"detail"`
	Direction string `json:"direction"` // "request" = 命中于请求体（用户输入侧）；"response" = 命中于响应体（模型输出侧）
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
