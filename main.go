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
	"fmt"
	"strings"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	pluginName = "ai-context-manager"
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

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ContextManagerConfig contains configuration for context management
type ContextManagerConfig struct {
	// MaxMessages limits the number of messages in context (0 = unlimited)
	MaxMessages int `json:"max_messages"`
	// MaxTokens limits the total token count (approximate, 0 = unlimited)
	MaxTokens int `json:"max_tokens"`
	// PreserveSystemMessage keeps the first system message regardless of limits
	PreserveSystemMessage bool `json:"preserve_system_message"`
	// PreserveLastN keeps the last N messages regardless of limits
	PreserveLastN int `json:"preserve_last_n"`
	// SummarizeStrategy defines how to manage context: "truncate", "sliding_window", or "compaction"
	SummarizeStrategy string `json:"summarize_strategy"`
	// TokenEstimateRatio is the approximate characters per token ratio
	TokenEstimateRatio float64 `json:"token_estimate_ratio"`
	// MemoryKey is the header key to retrieve session memory
	MemoryKey string `json:"memory_key"`
	// InjectMemory indicates whether to inject memory into context
	InjectMemory bool `json:"inject_memory"`

	// --- Context Compression / Compaction (Google ADK inspired) ---

	// CompactionInterval is the number of conversation turns (user-assistant pairs)
	// after which context compaction is triggered (0 = use max_messages/max_tokens as trigger)
	CompactionInterval int `json:"compaction_interval"`
	// OverlapSize is the number of recent messages to keep uncompressed alongside the
	// compacted summary for context continuity (similar to ADK's overlap_size)
	OverlapSize int `json:"overlap_size"`
	// TokenThreshold triggers compaction when the estimated total token count exceeds
	// this value (0 = disabled). This is an alternative trigger to compaction_interval.
	TokenThreshold int `json:"token_threshold"`
	// CompactionSummaryTemplate is the template for creating summary messages.
	// Use {summary} as a placeholder for the extracted summary content.
	CompactionSummaryTemplate string `json:"compaction_summary_template"`

	// --- Scoped State Management (Google ADK inspired) ---

	// StateScope defines the scope prefix for state management.
	// Supported values: "session" (default), "user", "app", "temp"
	StateScope string `json:"state_scope"`
	// StateHeaderPrefix is the prefix for state-related headers
	StateHeaderPrefix string `json:"state_header_prefix"`
}

func parseConfig(json gjson.Result, config *ContextManagerConfig) error {
	// Set defaults
	config.MaxMessages = 0 // unlimited
	config.MaxTokens = 0   // unlimited
	config.PreserveSystemMessage = true
	config.PreserveLastN = 2
	config.SummarizeStrategy = "sliding_window"
	config.TokenEstimateRatio = 4.0 // ~4 chars per token for English
	config.MemoryKey = "x-session-memory"
	config.InjectMemory = false
	config.CompactionInterval = 0
	config.OverlapSize = 1
	config.TokenThreshold = 0
	config.CompactionSummaryTemplate = "[Context Summary] The following is a summary of the previous conversation:\n{summary}"
	config.StateScope = "session"
	config.StateHeaderPrefix = "x-context-state"

	// Parse max_messages
	if json.Get("max_messages").Exists() {
		config.MaxMessages = int(json.Get("max_messages").Int())
	}

	// Parse max_tokens
	if json.Get("max_tokens").Exists() {
		config.MaxTokens = int(json.Get("max_tokens").Int())
	}

	// Parse preserve_system_message
	if json.Get("preserve_system_message").Exists() {
		config.PreserveSystemMessage = json.Get("preserve_system_message").Bool()
	}

	// Parse preserve_last_n
	if json.Get("preserve_last_n").Exists() {
		config.PreserveLastN = int(json.Get("preserve_last_n").Int())
	}

	// Parse summarize_strategy
	if json.Get("summarize_strategy").Exists() {
		config.SummarizeStrategy = json.Get("summarize_strategy").String()
	}

	// Parse token_estimate_ratio
	if json.Get("token_estimate_ratio").Exists() {
		config.TokenEstimateRatio = json.Get("token_estimate_ratio").Float()
	}

	// Parse memory_key
	if json.Get("memory_key").Exists() {
		config.MemoryKey = json.Get("memory_key").String()
	}

	// Parse inject_memory
	if json.Get("inject_memory").Exists() {
		config.InjectMemory = json.Get("inject_memory").Bool()
	}

	// Parse compaction_interval
	if json.Get("compaction_interval").Exists() {
		config.CompactionInterval = int(json.Get("compaction_interval").Int())
	}

	// Parse overlap_size
	if json.Get("overlap_size").Exists() {
		config.OverlapSize = int(json.Get("overlap_size").Int())
	}

	// Parse token_threshold
	if json.Get("token_threshold").Exists() {
		config.TokenThreshold = int(json.Get("token_threshold").Int())
	}

	// Parse compaction_summary_template
	if json.Get("compaction_summary_template").Exists() {
		config.CompactionSummaryTemplate = json.Get("compaction_summary_template").String()
	}

	// Parse state_scope
	if json.Get("state_scope").Exists() {
		config.StateScope = json.Get("state_scope").String()
	}

	// Parse state_header_prefix
	if json.Get("state_header_prefix").Exists() {
		config.StateHeaderPrefix = json.Get("state_header_prefix").String()
	}

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config ContextManagerConfig) types.Action {
	ctx.DisableReroute()
	proxywasm.RemoveHttpRequestHeader("content-length")

	// Check for memory injection
	if config.InjectMemory && config.MemoryKey != "" {
		memory, _ := proxywasm.GetHttpRequestHeader(config.MemoryKey)
		if memory != "" {
			ctx.SetContext("session_memory", memory)
		}
	}

	// Handle scoped state management: read state from headers with scope prefix
	if config.StateHeaderPrefix != "" {
		scopeKey := buildScopeKey(config.StateScope, "data")
		stateHeader := config.StateHeaderPrefix + "-" + config.StateScope
		stateData, _ := proxywasm.GetHttpRequestHeader(stateHeader)
		if stateData != "" {
			ctx.SetContext(scopeKey, stateData)
		}
	}

	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config ContextManagerConfig, body []byte) types.Action {
	// Parse messages from request body
	messages := gjson.GetBytes(body, "messages")
	if !messages.Exists() {
		return types.ActionContinue
	}

	// Parse messages into structs
	var msgList []Message
	for _, msg := range messages.Array() {
		msgList = append(msgList, Message{
			Role:    msg.Get("role").String(),
			Content: msg.Get("content").String(),
		})
	}

	// Inject memory if available
	if config.InjectMemory {
		if memory, ok := ctx.GetContext("session_memory").(string); ok && memory != "" {
			msgList = injectMemory(msgList, memory)
		}
	}

	// Apply context management
	processedMessages := manageContext(msgList, config)

	// Rebuild request body with processed messages
	if len(processedMessages) != len(msgList) || hasContentChanged(msgList, processedMessages) {
		newBody, err := rebuildRequestBody(body, processedMessages)
		if err != nil {
			log.Errorf("Failed to rebuild request body: %v", err)
			return types.ActionContinue
		}

		if err := proxywasm.ReplaceHttpRequestBody(newBody); err != nil {
			log.Errorf("Failed to replace request body: %v", err)
		}
	}

	return types.ActionContinue
}

// manageContext applies context management rules to the message list
func manageContext(messages []Message, config ContextManagerConfig) []Message {
	if len(messages) == 0 {
		return messages
	}

	// If no limits set and not using compaction, return original messages
	if config.MaxMessages == 0 && config.MaxTokens == 0 && config.SummarizeStrategy != "compaction" {
		return messages
	}

	result := make([]Message, 0, len(messages))

	// Identify system message if present
	var systemMessage *Message
	startIdx := 0
	if config.PreserveSystemMessage && len(messages) > 0 && messages[0].Role == "system" {
		systemMessage = &messages[0]
		startIdx = 1
	}

	// Get non-system messages
	nonSystemMessages := messages[startIdx:]

	// Apply limits based on strategy
	switch config.SummarizeStrategy {
	case "truncate":
		nonSystemMessages = applyTruncateStrategy(nonSystemMessages, config)
	case "compaction":
		nonSystemMessages = applyCompactionStrategy(nonSystemMessages, config)
	case "sliding_window":
		fallthrough
	default:
		nonSystemMessages = applySlidingWindowStrategy(nonSystemMessages, config)
	}

	// Rebuild result
	if systemMessage != nil {
		result = append(result, *systemMessage)
	}
	result = append(result, nonSystemMessages...)

	return result
}

// applyTruncateStrategy truncates messages from the beginning, preserving the last N
func applyTruncateStrategy(messages []Message, config ContextManagerConfig) []Message {
	if len(messages) == 0 {
		return messages
	}

	// Calculate how many messages to keep
	keepCount := len(messages)

	// Apply max_messages limit
	if config.MaxMessages > 0 && keepCount > config.MaxMessages {
		keepCount = config.MaxMessages
	}

	// Ensure we keep at least preserve_last_n
	if keepCount < config.PreserveLastN {
		keepCount = config.PreserveLastN
	}

	// Don't exceed actual message count
	if keepCount > len(messages) {
		keepCount = len(messages)
	}

	// Take last keepCount messages
	return messages[len(messages)-keepCount:]
}

// applySlidingWindowStrategy keeps recent messages within token/message limits
func applySlidingWindowStrategy(messages []Message, config ContextManagerConfig) []Message {
	if len(messages) == 0 {
		return messages
	}

	result := make([]Message, 0, len(messages))
	totalTokens := 0

	// Process from the end (most recent first)
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		msgTokens := estimateTokens(msg.Content, config.TokenEstimateRatio)

		// Check max_messages limit
		if config.MaxMessages > 0 && len(result) >= config.MaxMessages {
			break
		}

		// Check max_tokens limit
		if config.MaxTokens > 0 && totalTokens+msgTokens > config.MaxTokens {
			// Keep going if we haven't reached preserve_last_n
			if len(result) >= config.PreserveLastN {
				break
			}
		}

		// Prepend message (we're iterating backwards)
		result = append([]Message{msg}, result...)
		totalTokens += msgTokens
	}

	return result
}

// estimateTokens provides a rough token count estimation
func estimateTokens(text string, ratio float64) int {
	if ratio <= 0 {
		ratio = 4.0
	}
	return int(float64(len(text)) / ratio)
}

// estimateTotalTokens estimates the total token count for a list of messages
func estimateTotalTokens(messages []Message, ratio float64) int {
	total := 0
	for _, msg := range messages {
		total += estimateTokens(msg.Content, ratio)
	}
	return total
}

// shouldCompact determines whether compaction should be triggered based on configuration
func shouldCompact(messages []Message, config ContextManagerConfig) bool {
	// Check compaction_interval: count conversation turns (user-assistant pairs)
	if config.CompactionInterval > 0 {
		turns := countConversationTurns(messages)
		if turns >= config.CompactionInterval {
			return true
		}
	}

	// Check token_threshold
	if config.TokenThreshold > 0 {
		totalTokens := estimateTotalTokens(messages, config.TokenEstimateRatio)
		if totalTokens >= config.TokenThreshold {
			return true
		}
	}

	// Check max_messages
	if config.MaxMessages > 0 && len(messages) > config.MaxMessages {
		return true
	}

	// Check max_tokens
	if config.MaxTokens > 0 {
		totalTokens := estimateTotalTokens(messages, config.TokenEstimateRatio)
		if totalTokens > config.MaxTokens {
			return true
		}
	}

	return false
}

// countConversationTurns counts the number of user-assistant pairs in the messages
func countConversationTurns(messages []Message) int {
	turns := 0
	for _, msg := range messages {
		if msg.Role == "user" {
			turns++
		}
	}
	return turns
}

// applyCompactionStrategy compresses older messages into a summary message,
// keeping recent messages intact for context continuity (similar to Google ADK's
// EventsCompactionConfig with compaction_interval and overlap_size)
func applyCompactionStrategy(messages []Message, config ContextManagerConfig) []Message {
	if len(messages) == 0 {
		return messages
	}

	// Determine if compaction should be triggered
	if !shouldCompact(messages, config) {
		return messages
	}

	// Determine how many recent messages to keep (overlap)
	overlapSize := config.OverlapSize
	if overlapSize <= 0 {
		overlapSize = 1
	}

	// Also consider preserve_last_n
	keepRecent := overlapSize
	if config.PreserveLastN > keepRecent {
		keepRecent = config.PreserveLastN
	}

	// Don't compact if there aren't enough messages
	if len(messages) <= keepRecent {
		return messages
	}

	// Split messages: messages to compact vs. messages to keep
	compactBoundary := len(messages) - keepRecent
	messagesToCompact := messages[:compactBoundary]
	messagesToKeep := messages[compactBoundary:]

	// Create summary from older messages
	summary := compactMessages(messagesToCompact, config.CompactionSummaryTemplate)

	// Build result: summary message + recent messages
	result := make([]Message, 0, 1+len(messagesToKeep))
	result = append(result, summary)
	result = append(result, messagesToKeep...)

	return result
}

// compactMessages creates a summary message from a list of messages
func compactMessages(messages []Message, template string) Message {
	if len(messages) == 0 {
		return Message{Role: "system", Content: "No previous context."}
	}

	// Build extractive summary: extract key content from each message
	var summaryParts []string
	for _, msg := range messages {
		content := msg.Content
		// Truncate very long individual messages for the summary
		if len(content) > 200 {
			content = content[:200] + "..."
		}
		summaryParts = append(summaryParts, fmt.Sprintf("%s: %s", msg.Role, content))
	}

	summaryContent := strings.Join(summaryParts, "\n")

	// Apply template
	if template == "" {
		template = "[Context Summary] The following is a summary of the previous conversation:\n{summary}"
	}
	finalContent := strings.Replace(template, "{summary}", summaryContent, 1)

	return Message{
		Role:    "system",
		Content: finalContent,
	}
}

// buildScopeKey creates a scoped key for state management (similar to ADK's state prefix system)
func buildScopeKey(scope, key string) string {
	if scope == "" {
		scope = "session"
	}
	return scope + ":" + key
}

// injectMemory adds session memory to the context
func injectMemory(messages []Message, memory string) []Message {
	if memory == "" {
		return messages
	}

	// Parse memory as JSON array of messages
	var memoryMessages []Message
	if err := json.Unmarshal([]byte(memory), &memoryMessages); err != nil {
		// Try as a single message
		memoryMessages = []Message{{
			Role:    "system",
			Content: "Previous conversation context: " + memory,
		}}
	}

	// Find insert position (after system message if present)
	insertIdx := 0
	if len(messages) > 0 && messages[0].Role == "system" {
		insertIdx = 1
	}

	// Insert memory messages
	result := make([]Message, 0, len(messages)+len(memoryMessages))
	result = append(result, messages[:insertIdx]...)
	result = append(result, memoryMessages...)
	result = append(result, messages[insertIdx:]...)

	return result
}

// hasContentChanged checks if message content has changed
func hasContentChanged(original, processed []Message) bool {
	if len(original) != len(processed) {
		return true
	}
	for i := range original {
		if original[i].Role != processed[i].Role || original[i].Content != processed[i].Content {
			return true
		}
	}
	return false
}

// rebuildRequestBody rebuilds the request body with new messages
func rebuildRequestBody(originalBody []byte, messages []Message) ([]byte, error) {
	// Convert messages to JSON
	messagesJSON, err := json.Marshal(messages)
	if err != nil {
		return nil, err
	}

	// Replace messages in original body
	newBody, err := sjson.SetRaw(string(originalBody), "messages", string(messagesJSON))
	if err != nil {
		return nil, err
	}

	return []byte(newBody), nil
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
