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

	// Compiled patterns (internal use)
	compiledDenyPatterns  []*regexp.Regexp
	compiledAllowPatterns []*regexp.Regexp
}

func parseConfig(json gjson.Result, config *PromptGuardConfig) error {
	// Set defaults
	config.DenyCode = 403
	config.DenyMessage = "Request blocked by prompt guard"
	config.CaseSensitive = false

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

		// Check if content matches deny patterns
		if matchesAnyPattern(content, config.compiledDenyPatterns) {
			log.Infof("Malicious prompt detected, blocking request")
			sendDenyResponse(config.DenyCode, config.DenyMessage)
			return types.ActionContinue
		}
	}

	return types.ActionContinue
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
