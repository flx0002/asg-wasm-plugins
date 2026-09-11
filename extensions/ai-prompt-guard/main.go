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
	)
}

// PromptGuardConfig contains configuration for malicious prompt detection
type PromptGuardConfig struct {
	// DenyPatterns contains regex patterns to block malicious prompts
	DenyPatterns []string `json:"deny_patterns"`
	// AllowPatterns contains regex patterns to explicitly allow (bypass deny)
	AllowPatterns []string `json:"allow_patterns"`
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
	compiledDenyPatterns  []*regexp.Regexp
	compiledAllowPatterns []*regexp.Regexp
}

func parseConfig(json gjson.Result, config *PromptGuardConfig) error {
	// Set defaults
	config.DenyCode = 403
	config.DenyMessage = "Request blocked by prompt guard"
	config.CaseSensitive = false
	config.EnableNormalization = true
	config.MaxDecodeCandidates = defaultMaxCandidates

	if json.Get("enable_normalization").Exists() {
		config.EnableNormalization = json.Get("enable_normalization").Bool()
	}
	if json.Get("max_decode_candidates").Exists() {
		config.MaxDecodeCandidates = int(json.Get("max_decode_candidates").Int())
	}

	// Parse deny_code
	if json.Get("deny_code").Exists() {
		config.DenyCode = int(json.Get("deny_code").Int())
	}

	// Parse deny_message
	if json.Get("deny_message").Exists() {
		config.DenyMessage = json.Get("deny_message").String()
	}

	// Parse case_sensitive
	if json.Get("case_sensitive").Exists() {
		config.CaseSensitive = json.Get("case_sensitive").Bool()
	}

	// Parse deny_patterns
	denyPatterns := json.Get("deny_patterns").Array()
	config.DenyPatterns = make([]string, 0, len(denyPatterns))
	config.compiledDenyPatterns = make([]*regexp.Regexp, 0, len(denyPatterns))
	for _, pattern := range denyPatterns {
		patternStr := pattern.String()
		config.DenyPatterns = append(config.DenyPatterns, patternStr)

		var re *regexp.Regexp
		var err error
		if config.CaseSensitive {
			re, err = regexp.Compile(patternStr)
		} else {
			re, err = regexp.Compile("(?i)" + patternStr)
		}
		if err != nil {
			log.Warnf("Invalid deny pattern '%s': %v", patternStr, err)
			continue
		}
		config.compiledDenyPatterns = append(config.compiledDenyPatterns, re)
	}

	// Parse allow_patterns
	allowPatterns := json.Get("allow_patterns").Array()
	config.AllowPatterns = make([]string, 0, len(allowPatterns))
	config.compiledAllowPatterns = make([]*regexp.Regexp, 0, len(allowPatterns))
	for _, pattern := range allowPatterns {
		patternStr := pattern.String()
		config.AllowPatterns = append(config.AllowPatterns, patternStr)

		var re *regexp.Regexp
		var err error
		if config.CaseSensitive {
			re, err = regexp.Compile(patternStr)
		} else {
			re, err = regexp.Compile("(?i)" + patternStr)
		}
		if err != nil {
			log.Warnf("Invalid allow pattern '%s': %v", patternStr, err)
			continue
		}
		config.compiledAllowPatterns = append(config.compiledAllowPatterns, re)
	}

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config PromptGuardConfig) types.Action {
	ctx.DisableReroute()
	proxywasm.RemoveHttpRequestHeader("content-length")
	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config PromptGuardConfig, body []byte) types.Action {
	// Extract messages from request body
	messages := gjson.GetBytes(body, "messages")
	if !messages.Exists() {
		log.Debugf("No messages field found in request body")
		return types.ActionContinue
	}

	// Check each message
	for _, msg := range messages.Array() {
		content := msg.Get("content").String()
		if content == "" {
			continue
		}

		// Check if content matches allow patterns (bypass deny check)
		if matchesAnyPattern(content, config.compiledAllowPatterns) {
			log.Debugf("Content matches allow pattern, bypassing deny check")
			continue
		}

		// Check deny patterns: plain text first, then decoded variants (R3)
		if hit, method := detectMalicious(content, config); hit {
			log.Infof("Malicious prompt detected (method=%s), blocking request", method)
			detail := "Detected prompt injection / jailbreak pattern in user message"
			if method != "plain" {
				detail = detail + " (decoded via " + method + ")"
			}
			// 写入安全事件到 Dynamic Metadata，供 ai-agent-guard 收集并记录审计日志
			appendSecurityEvent(SecurityEvent{
				Type:     "prompt_injection",
				Severity: "high",
				Source:   "ai-prompt-guard",
				Score:    80,
				Detail:   detail,
			})
			sendDenyResponse(config.DenyCode, config.DenyMessage)
			return types.ActionContinue
		}
	}

	return types.ActionContinue
}

// detectMalicious checks content against deny patterns.
// Returns (hit, method); method is "plain" or the decoding method that exposed the hit.
func detectMalicious(content string, config PromptGuardConfig) (bool, string) {
	if matchesAnyPattern(content, config.compiledDenyPatterns) {
		return true, "plain"
	}
	if !config.EnableNormalization {
		return false, ""
	}
	for _, c := range NormalizeForDetection(content, config.MaxDecodeCandidates) {
		if c.Method == "original" {
			continue
		}
		if matchesAnyPattern(c.Text, config.compiledDenyPatterns) {
			return true, c.Method
		}
	}
	return false, ""
}

// matchesAnyPattern checks if text matches any of the compiled patterns
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
