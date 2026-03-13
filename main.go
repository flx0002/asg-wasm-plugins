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
		wrapper.ProcessResponseHeaders(onHttpResponseHeaders),
		wrapper.ProcessResponseBody(onHttpResponseBody),
	)
}

// Message represents a chat message with support for tool calls and function calls
type Message struct {
	Role         string      `json:"role"`
	Content      string      `json:"content"`
	ToolCalls    interface{} `json:"tool_calls,omitempty"`
	ToolCallID   string      `json:"tool_call_id,omitempty"`
	FunctionCall interface{} `json:"function_call,omitempty"`
	Name         string      `json:"name,omitempty"`
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

	// --- Turn-pair Integrity (Google ADK inspired) ---

	// PreserveTurnPairs ensures user-assistant message pairs are kept as atomic units
	// during compaction/truncation. If true, when removing messages, the paired
	// assistant response is also removed with its user message (and vice versa).
	PreserveTurnPairs bool `json:"preserve_turn_pairs"`

	// --- Instruction Pinning (Google ADK inspired) ---

	// PinnedMessageRoles specifies additional message roles to always preserve
	// beyond the system message. Messages with these roles are never evicted.
	// e.g., ["tool", "function"] to keep tool/function call results
	PinnedMessageRoles []string `json:"pinned_message_roles"`

	// --- Context Caching Hints (Google ADK ContextCacheConfig inspired) ---

	// CacheSystemPrompt enables caching hints for system prompt. When enabled,
	// adds x-context-cache-status response header to indicate cacheable content.
	CacheSystemPrompt bool `json:"cache_system_prompt"`
	// CacheMinTokens is the minimum token count for a system prompt to be
	// considered for caching (similar to ADK's min_tokens). Default: 0 (always cache).
	CacheMinTokens int `json:"cache_min_tokens"`

	// --- Response Context Tracking (Google ADK lifecycle processing inspired) ---

	// TrackTokenUsage enables response processing to extract and forward
	// token usage metadata from model responses.
	TrackTokenUsage bool `json:"track_token_usage"`
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
	config.PreserveTurnPairs = false
	config.PinnedMessageRoles = nil
	config.CacheSystemPrompt = false
	config.CacheMinTokens = 0
	config.TrackTokenUsage = false

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

	// Parse preserve_turn_pairs
	if json.Get("preserve_turn_pairs").Exists() {
		config.PreserveTurnPairs = json.Get("preserve_turn_pairs").Bool()
	}

	// Parse pinned_message_roles
	if json.Get("pinned_message_roles").Exists() {
		for _, role := range json.Get("pinned_message_roles").Array() {
			config.PinnedMessageRoles = append(config.PinnedMessageRoles, role.String())
		}
	}

	// Parse cache_system_prompt
	if json.Get("cache_system_prompt").Exists() {
		config.CacheSystemPrompt = json.Get("cache_system_prompt").Bool()
	}

	// Parse cache_min_tokens
	if json.Get("cache_min_tokens").Exists() {
		config.CacheMinTokens = int(json.Get("cache_min_tokens").Int())
	}

	// Parse track_token_usage
	if json.Get("track_token_usage").Exists() {
		config.TrackTokenUsage = json.Get("track_token_usage").Bool()
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

	// Parse messages into structs with tool/function call support
	var msgList []Message
	for _, msg := range messages.Array() {
		m := Message{
			Role:    msg.Get("role").String(),
			Content: msg.Get("content").String(),
		}
		// Preserve tool_calls field
		if msg.Get("tool_calls").Exists() {
			m.ToolCalls = msg.Get("tool_calls").Value()
		}
		// Preserve tool_call_id field
		if msg.Get("tool_call_id").Exists() {
			m.ToolCallID = msg.Get("tool_call_id").String()
		}
		// Preserve function_call field
		if msg.Get("function_call").Exists() {
			m.FunctionCall = msg.Get("function_call").Value()
		}
		// Preserve name field
		if msg.Get("name").Exists() {
			m.Name = msg.Get("name").String()
		}
		msgList = append(msgList, m)
	}

	// Context caching hints: check if system prompt is cache-eligible
	if config.CacheSystemPrompt && len(msgList) > 0 && msgList[0].Role == "system" {
		sysTokens := estimateTokens(msgList[0].Content, config.TokenEstimateRatio)
		if sysTokens >= config.CacheMinTokens {
			ctx.SetContext("cache_system_prompt", "true")
			ctx.SetContext("system_prompt_tokens", itoa(sysTokens))
		}
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

	// Extract pinned messages (messages with pinned roles that must be preserved)
	var pinnedMessages []Message
	var unpinnedMessages []Message
	if len(config.PinnedMessageRoles) > 0 {
		pinnedMessages, unpinnedMessages = extractPinnedMessages(nonSystemMessages, config.PinnedMessageRoles)
	} else {
		unpinnedMessages = nonSystemMessages
	}

	// Apply limits based on strategy to unpinned messages only
	switch config.SummarizeStrategy {
	case "truncate":
		unpinnedMessages = applyTruncateStrategy(unpinnedMessages, config)
	case "compaction":
		unpinnedMessages = applyCompactionStrategy(unpinnedMessages, config)
	case "sliding_window":
		fallthrough
	default:
		unpinnedMessages = applySlidingWindowStrategy(unpinnedMessages, config)
	}

	// Apply turn-pair integrity if enabled
	if config.PreserveTurnPairs {
		unpinnedMessages = ensureTurnPairIntegrity(unpinnedMessages)
	}

	// Rebuild result: system + pinned + processed unpinned
	if systemMessage != nil {
		result = append(result, *systemMessage)
	}
	result = append(result, pinnedMessages...)
	result = append(result, unpinnedMessages...)

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

// extractPinnedMessages separates messages with pinned roles from the rest
func extractPinnedMessages(messages []Message, pinnedRoles []string) (pinned []Message, unpinned []Message) {
	roleSet := make(map[string]bool, len(pinnedRoles))
	for _, role := range pinnedRoles {
		roleSet[role] = true
	}

	for _, msg := range messages {
		if roleSet[msg.Role] {
			pinned = append(pinned, msg)
		} else {
			unpinned = append(unpinned, msg)
		}
	}
	return
}

// ensureTurnPairIntegrity ensures user-assistant message pairs are kept as atomic units.
// If a user message exists without its following assistant response (or vice versa),
// the orphaned message is removed to maintain pair integrity.
func ensureTurnPairIntegrity(messages []Message) []Message {
	if len(messages) == 0 {
		return messages
	}

	result := make([]Message, 0, len(messages))
	i := 0
	for i < len(messages) {
		msg := messages[i]

		// Handle tool/function messages: keep them as-is (they don't form user-assistant pairs)
		if isToolMessage(msg) {
			result = append(result, msg)
			i++
			continue
		}

		// Handle compaction summary messages (system role from compaction)
		if msg.Role == "system" {
			result = append(result, msg)
			i++
			continue
		}

		// Look for user-assistant pair
		if msg.Role == "user" {
			if i+1 < len(messages) && messages[i+1].Role == "assistant" {
				// Complete pair: keep both
				result = append(result, msg, messages[i+1])
				i += 2
			} else {
				// Orphan user at the end of the list - keep it (it's the latest query)
				result = append(result, msg)
				i++
			}
		} else if msg.Role == "assistant" {
			// Orphaned assistant without preceding user - skip it
			i++
		} else {
			// Unknown role, keep it
			result = append(result, msg)
			i++
		}
	}

	return result
}

// isToolMessage checks if a message is a tool call or tool result
func isToolMessage(msg Message) bool {
	if msg.Role == "tool" || msg.Role == "function" ||
		msg.ToolCallID != "" {
		return true
	}
	// Check ToolCalls: non-nil and non-empty
	if msg.ToolCalls != nil {
		if arr, ok := msg.ToolCalls.([]interface{}); ok {
			return len(arr) > 0
		}
		return true // non-slice type, still counts
	}
	// Check FunctionCall: non-nil
	if msg.FunctionCall != nil {
		return true
	}
	return false
}

// onHttpResponseHeaders processes response headers for context tracking
func onHttpResponseHeaders(ctx wrapper.HttpContext, config ContextManagerConfig) types.Action {
	// Add context cache status header if caching is enabled
	if config.CacheSystemPrompt {
		if cacheStatus, ok := ctx.GetContext("cache_system_prompt").(string); ok && cacheStatus == "true" {
			if tokens, ok := ctx.GetContext("system_prompt_tokens").(string); ok {
				proxywasm.AddHttpResponseHeader("x-context-cache-status", "eligible")
				proxywasm.AddHttpResponseHeader("x-context-cache-tokens", tokens)
			}
		}
	}

	// Buffer response body if we need to track token usage
	if config.TrackTokenUsage {
		ctx.BufferResponseBody()
	}

	return types.ActionContinue
}

// onHttpResponseBody processes response body for context metadata extraction
func onHttpResponseBody(ctx wrapper.HttpContext, config ContextManagerConfig, body []byte) types.Action {
	if !config.TrackTokenUsage {
		return types.ActionContinue
	}

	// Extract token usage from response (OpenAI-compatible format)
	usage := gjson.GetBytes(body, "usage")
	if usage.Exists() {
		promptTokens := usage.Get("prompt_tokens").String()
		completionTokens := usage.Get("completion_tokens").String()
		totalTokens := usage.Get("total_tokens").String()

		if promptTokens != "" {
			proxywasm.AddHttpResponseHeader("x-context-prompt-tokens", promptTokens)
		}
		if completionTokens != "" {
			proxywasm.AddHttpResponseHeader("x-context-completion-tokens", completionTokens)
		}
		if totalTokens != "" {
			proxywasm.AddHttpResponseHeader("x-context-total-tokens", totalTokens)
		}
	}

	return types.ActionContinue
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
