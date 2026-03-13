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
	"strings"
	"testing"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/test"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// Test configuration with message limit
var messageLimitConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"max_messages":            5,
		"preserve_system_message": true,
		"preserve_last_n":         2,
		"summarize_strategy":      "sliding_window",
	})
	return data
}()

// Test configuration with token limit
var tokenLimitConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"max_tokens":              100,
		"preserve_system_message": true,
		"preserve_last_n":         1,
		"token_estimate_ratio":    4.0,
	})
	return data
}()

// Test configuration with memory injection
var memoryConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"inject_memory":           true,
		"memory_key":              "x-session-memory",
		"preserve_system_message": true,
	})
	return data
}()

// Empty configuration (no limits)
var emptyContextConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{})
	return data
}()

func TestParseConfigContext(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("parse message limit config", func(t *testing.T) {
			host, status := test.NewTestHost(messageLimitConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			ctxConfig := config.(*ContextManagerConfig)
			require.Equal(t, 5, ctxConfig.MaxMessages)
			require.True(t, ctxConfig.PreserveSystemMessage)
			require.Equal(t, 2, ctxConfig.PreserveLastN)
			require.Equal(t, "sliding_window", ctxConfig.SummarizeStrategy)
		})

		t.Run("parse token limit config", func(t *testing.T) {
			host, status := test.NewTestHost(tokenLimitConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			ctxConfig := config.(*ContextManagerConfig)
			require.Equal(t, 100, ctxConfig.MaxTokens)
			require.Equal(t, 1, ctxConfig.PreserveLastN)
			require.Equal(t, 4.0, ctxConfig.TokenEstimateRatio)
		})

		t.Run("parse memory config", func(t *testing.T) {
			host, status := test.NewTestHost(memoryConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			ctxConfig := config.(*ContextManagerConfig)
			require.True(t, ctxConfig.InjectMemory)
			require.Equal(t, "x-session-memory", ctxConfig.MemoryKey)
		})

		t.Run("parse empty config uses defaults", func(t *testing.T) {
			host, status := test.NewTestHost(emptyContextConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			ctxConfig := config.(*ContextManagerConfig)
			require.Equal(t, 0, ctxConfig.MaxMessages)
			require.Equal(t, 0, ctxConfig.MaxTokens)
			require.True(t, ctxConfig.PreserveSystemMessage)
			require.Equal(t, 2, ctxConfig.PreserveLastN)
		})
	})
}

func TestManageContext(t *testing.T) {
	t.Run("no limits returns original", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:           0,
			MaxTokens:             0,
			PreserveSystemMessage: true,
		}
		messages := []Message{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
		}
		result := manageContext(messages, config)
		require.Len(t, result, 3)
	})

	t.Run("respects message limit", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:           3,
			PreserveSystemMessage: true,
			PreserveLastN:         2,
			SummarizeStrategy:     "sliding_window",
		}
		messages := []Message{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "Message 1"},
			{Role: "assistant", Content: "Response 1"},
			{Role: "user", Content: "Message 2"},
			{Role: "assistant", Content: "Response 2"},
			{Role: "user", Content: "Message 3"},
		}
		result := manageContext(messages, config)
		// Should have: system + 3 most recent messages (max_messages=3)
		require.Len(t, result, 4)
		require.Equal(t, "system", result[0].Role)
		require.Equal(t, "Message 3", result[len(result)-1].Content)
	})

	t.Run("preserves system message", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:           2,
			PreserveSystemMessage: true,
			PreserveLastN:         1,
			SummarizeStrategy:     "sliding_window",
		}
		messages := []Message{
			{Role: "system", Content: "System prompt"},
			{Role: "user", Content: "Old message"},
			{Role: "assistant", Content: "Old response"},
			{Role: "user", Content: "New message"},
		}
		result := manageContext(messages, config)
		require.True(t, len(result) >= 2)
		require.Equal(t, "system", result[0].Role)
		require.Equal(t, "System prompt", result[0].Content)
	})

	t.Run("empty messages returns empty", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages: 5,
		}
		result := manageContext([]Message{}, config)
		require.Len(t, result, 0)
	})
}

func TestEstimateTokens(t *testing.T) {
	t.Run("estimates tokens with default ratio", func(t *testing.T) {
		// 40 characters / 4 = 10 tokens
		text := "This is a test message with some content"
		tokens := estimateTokens(text, 4.0)
		require.Equal(t, 10, tokens)
	})

	t.Run("handles zero ratio", func(t *testing.T) {
		text := "Hello"
		tokens := estimateTokens(text, 0)
		require.Equal(t, 1, tokens) // 5/4 = 1
	})

	t.Run("empty text returns zero", func(t *testing.T) {
		tokens := estimateTokens("", 4.0)
		require.Equal(t, 0, tokens)
	})
}

func TestInjectMemory(t *testing.T) {
	t.Run("injects memory as JSON array", func(t *testing.T) {
		messages := []Message{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "Hello"},
		}
		memory := `[{"role":"assistant","content":"Previous context"}]`
		result := injectMemory(messages, memory)
		require.Len(t, result, 3)
		// Memory should be after system message
		require.Equal(t, "system", result[0].Role)
		require.Equal(t, "assistant", result[1].Role)
		require.Equal(t, "Previous context", result[1].Content)
	})

	t.Run("injects memory as plain text", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Hello"},
		}
		memory := "User previously asked about weather"
		result := injectMemory(messages, memory)
		require.Len(t, result, 2)
		require.Contains(t, result[0].Content, "Previous conversation context")
	})

	t.Run("empty memory returns original", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Hello"},
		}
		result := injectMemory(messages, "")
		require.Len(t, result, 1)
	})
}

func TestApplySlidingWindowStrategy(t *testing.T) {
	t.Run("keeps messages within limit", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:    3,
			PreserveLastN:  1,
			SummarizeStrategy: "sliding_window",
		}
		messages := []Message{
			{Role: "user", Content: "Msg 1"},
			{Role: "assistant", Content: "Resp 1"},
			{Role: "user", Content: "Msg 2"},
			{Role: "assistant", Content: "Resp 2"},
			{Role: "user", Content: "Msg 3"},
		}
		result := applySlidingWindowStrategy(messages, config)
		require.Len(t, result, 3)
		require.Equal(t, "Msg 3", result[len(result)-1].Content)
	})
}

func TestApplyTruncateStrategy(t *testing.T) {
	t.Run("truncates from beginning", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:   2,
			PreserveLastN: 1,
		}
		messages := []Message{
			{Role: "user", Content: "Msg 1"},
			{Role: "assistant", Content: "Resp 1"},
			{Role: "user", Content: "Msg 2"},
		}
		result := applyTruncateStrategy(messages, config)
		require.Len(t, result, 2)
		require.Equal(t, "Msg 2", result[len(result)-1].Content)
	})
}

func TestOnHttpRequestBodyContext(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("manages context in request body", func(t *testing.T) {
			host, status := test.NewTestHost(messageLimitConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "example.com"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
			})

			// Create body with many messages
			body := `{
				"model": "gpt-3.5-turbo",
				"messages": [
					{"role": "system", "content": "You are helpful"},
					{"role": "user", "content": "Msg 1"},
					{"role": "assistant", "content": "Resp 1"},
					{"role": "user", "content": "Msg 2"},
					{"role": "assistant", "content": "Resp 2"},
					{"role": "user", "content": "Msg 3"},
					{"role": "assistant", "content": "Resp 3"},
					{"role": "user", "content": "Msg 4"}
				]
			}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)

			// Get the modified body
			modifiedBody := host.GetRequestBody()
			require.NotEmpty(t, modifiedBody)

			// Parse and verify
			messages := gjson.GetBytes(modifiedBody, "messages")
			require.True(t, messages.Exists())

			// Should have reduced messages (system + max_messages)
			require.LessOrEqual(t, len(messages.Array()), 6) // system + 5 messages max
		})

		t.Run("handles missing messages field", func(t *testing.T) {
			host, status := test.NewTestHost(messageLimitConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "example.com"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
			})

			body := `{"model": "gpt-3.5-turbo"}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)
		})

		t.Run("no limit config passes through", func(t *testing.T) {
			host, status := test.NewTestHost(emptyContextConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "example.com"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
			})

			body := `{
				"model": "gpt-3.5-turbo",
				"messages": [
					{"role": "user", "content": "Hello"},
					{"role": "assistant", "content": "Hi!"}
				]
			}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)
		})
	})
}

func TestHasContentChanged(t *testing.T) {
	t.Run("detects length change", func(t *testing.T) {
		original := []Message{{Role: "user", Content: "Hello"}}
		processed := []Message{}
		require.True(t, hasContentChanged(original, processed))
	})

	t.Run("detects content change", func(t *testing.T) {
		original := []Message{{Role: "user", Content: "Hello"}}
		processed := []Message{{Role: "user", Content: "Hi"}}
		require.True(t, hasContentChanged(original, processed))
	})

	t.Run("detects no change", func(t *testing.T) {
		original := []Message{{Role: "user", Content: "Hello"}}
		processed := []Message{{Role: "user", Content: "Hello"}}
		require.False(t, hasContentChanged(original, processed))
	})
}

func TestRebuildRequestBody(t *testing.T) {
	t.Run("rebuilds body with new messages", func(t *testing.T) {
		original := []byte(`{"model":"gpt-3.5","messages":[{"role":"user","content":"old"}]}`)
		newMessages := []Message{{Role: "user", Content: "new"}}
		result, err := rebuildRequestBody(original, newMessages)
		require.NoError(t, err)
		require.Contains(t, string(result), "new")
		require.Contains(t, string(result), "gpt-3.5")
	})
}

// --- Tests for new Google ADK-inspired features ---

// Test configuration for compaction strategy
var compactionConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"summarize_strategy":         "compaction",
		"compaction_interval":        3,
		"overlap_size":               2,
		"preserve_system_message":    true,
		"preserve_last_n":            2,
		"compaction_summary_template": "[Summary] Previous context:\n{summary}",
	})
	return data
}()

// Test configuration for token threshold compaction
var tokenThresholdConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"summarize_strategy": "compaction",
		"token_threshold":    50,
		"overlap_size":       1,
		"preserve_last_n":    1,
		"token_estimate_ratio": 4.0,
	})
	return data
}()

// Test configuration for scoped state
var scopedStateConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"state_scope":          "user",
		"state_header_prefix":  "x-context-state",
		"inject_memory":        true,
		"memory_key":           "x-session-memory",
	})
	return data
}()

func TestParseConfigCompaction(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("parse compaction config", func(t *testing.T) {
			host, status := test.NewTestHost(compactionConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			ctxConfig := config.(*ContextManagerConfig)
			require.Equal(t, "compaction", ctxConfig.SummarizeStrategy)
			require.Equal(t, 3, ctxConfig.CompactionInterval)
			require.Equal(t, 2, ctxConfig.OverlapSize)
			require.Contains(t, ctxConfig.CompactionSummaryTemplate, "{summary}")
		})

		t.Run("parse token threshold config", func(t *testing.T) {
			host, status := test.NewTestHost(tokenThresholdConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			ctxConfig := config.(*ContextManagerConfig)
			require.Equal(t, "compaction", ctxConfig.SummarizeStrategy)
			require.Equal(t, 50, ctxConfig.TokenThreshold)
			require.Equal(t, 1, ctxConfig.OverlapSize)
		})

		t.Run("parse scoped state config", func(t *testing.T) {
			host, status := test.NewTestHost(scopedStateConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			ctxConfig := config.(*ContextManagerConfig)
			require.Equal(t, "user", ctxConfig.StateScope)
			require.Equal(t, "x-context-state", ctxConfig.StateHeaderPrefix)
		})

		t.Run("defaults for new fields", func(t *testing.T) {
			host, status := test.NewTestHost(emptyContextConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			ctxConfig := config.(*ContextManagerConfig)
			require.Equal(t, 0, ctxConfig.CompactionInterval)
			require.Equal(t, 1, ctxConfig.OverlapSize)
			require.Equal(t, 0, ctxConfig.TokenThreshold)
			require.Equal(t, "session", ctxConfig.StateScope)
			require.Equal(t, "x-context-state", ctxConfig.StateHeaderPrefix)
			require.Contains(t, ctxConfig.CompactionSummaryTemplate, "{summary}")
		})
	})
}

func TestCountConversationTurns(t *testing.T) {
	t.Run("counts user messages as turns", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
			{Role: "user", Content: "How are you?"},
			{Role: "assistant", Content: "Fine!"},
			{Role: "user", Content: "Bye"},
		}
		require.Equal(t, 3, countConversationTurns(messages))
	})

	t.Run("empty messages returns zero", func(t *testing.T) {
		require.Equal(t, 0, countConversationTurns([]Message{}))
	})

	t.Run("no user messages returns zero", func(t *testing.T) {
		messages := []Message{
			{Role: "assistant", Content: "Hi!"},
			{Role: "system", Content: "You are helpful"},
		}
		require.Equal(t, 0, countConversationTurns(messages))
	})
}

func TestEstimateTotalTokens(t *testing.T) {
	t.Run("calculates total tokens for multiple messages", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Hello World!"}, // 12 chars / 4 = 3 tokens
			{Role: "assistant", Content: "Hi there!"}, // 9 chars / 4 = 2 tokens
		}
		total := estimateTotalTokens(messages, 4.0)
		require.Equal(t, 5, total)
	})

	t.Run("empty messages returns zero", func(t *testing.T) {
		total := estimateTotalTokens([]Message{}, 4.0)
		require.Equal(t, 0, total)
	})
}

func TestShouldCompact(t *testing.T) {
	t.Run("triggers on compaction interval", func(t *testing.T) {
		config := ContextManagerConfig{
			CompactionInterval: 3,
			TokenEstimateRatio: 4.0,
		}
		messages := []Message{
			{Role: "user", Content: "Msg 1"},
			{Role: "assistant", Content: "Resp 1"},
			{Role: "user", Content: "Msg 2"},
			{Role: "assistant", Content: "Resp 2"},
			{Role: "user", Content: "Msg 3"},
		}
		require.True(t, shouldCompact(messages, config))
	})

	t.Run("does not trigger below interval", func(t *testing.T) {
		config := ContextManagerConfig{
			CompactionInterval: 5,
			TokenEstimateRatio: 4.0,
		}
		messages := []Message{
			{Role: "user", Content: "Msg 1"},
			{Role: "assistant", Content: "Resp 1"},
			{Role: "user", Content: "Msg 2"},
		}
		require.False(t, shouldCompact(messages, config))
	})

	t.Run("triggers on token threshold", func(t *testing.T) {
		config := ContextManagerConfig{
			TokenThreshold:     10,
			TokenEstimateRatio: 4.0,
		}
		messages := []Message{
			{Role: "user", Content: "This is a long message with many tokens that should exceed the threshold"},
		}
		require.True(t, shouldCompact(messages, config))
	})

	t.Run("triggers on max_messages", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:        2,
			TokenEstimateRatio: 4.0,
		}
		messages := []Message{
			{Role: "user", Content: "Msg 1"},
			{Role: "assistant", Content: "Resp 1"},
			{Role: "user", Content: "Msg 2"},
		}
		require.True(t, shouldCompact(messages, config))
	})

	t.Run("does not trigger when no thresholds set", func(t *testing.T) {
		config := ContextManagerConfig{
			TokenEstimateRatio: 4.0,
		}
		messages := []Message{
			{Role: "user", Content: "Hello"},
		}
		require.False(t, shouldCompact(messages, config))
	})
}

func TestCompactMessages(t *testing.T) {
	t.Run("creates summary from messages", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "What is the weather?"},
			{Role: "assistant", Content: "It's sunny today."},
			{Role: "user", Content: "What about tomorrow?"},
			{Role: "assistant", Content: "It might rain."},
		}
		template := "[Summary] Previous context:\n{summary}"
		result := compactMessages(messages, template)
		require.Equal(t, "system", result.Role)
		require.Contains(t, result.Content, "[Summary]")
		require.Contains(t, result.Content, "What is the weather?")
		require.Contains(t, result.Content, "It's sunny today.")
		require.Contains(t, result.Content, "What about tomorrow?")
		require.Contains(t, result.Content, "It might rain.")
	})

	t.Run("truncates long messages in summary", func(t *testing.T) {
		longContent := strings.Repeat("a", 300)
		messages := []Message{
			{Role: "user", Content: longContent},
		}
		result := compactMessages(messages, "{summary}")
		// Content should be truncated at 200 chars + "..."
		require.Contains(t, result.Content, "...")
		require.Less(t, len(result.Content), 300)
	})

	t.Run("empty messages returns placeholder", func(t *testing.T) {
		result := compactMessages([]Message{}, "{summary}")
		require.Equal(t, "system", result.Role)
		require.Equal(t, "No previous context.", result.Content)
	})

	t.Run("uses default template when empty", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Hello"},
		}
		result := compactMessages(messages, "")
		require.Contains(t, result.Content, "[Context Summary]")
	})
}

func TestApplyCompactionStrategy(t *testing.T) {
	t.Run("compacts older messages and keeps recent", func(t *testing.T) {
		config := ContextManagerConfig{
			CompactionInterval:        3,
			OverlapSize:               2,
			PreserveLastN:             2,
			TokenEstimateRatio:        4.0,
			CompactionSummaryTemplate: "[Summary]\n{summary}",
		}
		messages := []Message{
			{Role: "user", Content: "Message 1"},
			{Role: "assistant", Content: "Response 1"},
			{Role: "user", Content: "Message 2"},
			{Role: "assistant", Content: "Response 2"},
			{Role: "user", Content: "Message 3"},
			{Role: "assistant", Content: "Response 3"},
		}
		result := applyCompactionStrategy(messages, config)

		// Should have: 1 summary + 2 recent messages (overlap_size=2)
		require.Len(t, result, 3)
		require.Equal(t, "system", result[0].Role)
		require.Contains(t, result[0].Content, "[Summary]")
		require.Contains(t, result[0].Content, "Message 1") // compacted content
		require.Equal(t, "Message 3", result[1].Content)    // kept recent
		require.Equal(t, "Response 3", result[2].Content)   // kept recent
	})

	t.Run("preserves all when below threshold", func(t *testing.T) {
		config := ContextManagerConfig{
			CompactionInterval:        10, // high interval, won't trigger
			OverlapSize:               2,
			PreserveLastN:             2,
			TokenEstimateRatio:        4.0,
			CompactionSummaryTemplate: "{summary}",
		}
		messages := []Message{
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
		}
		result := applyCompactionStrategy(messages, config)
		require.Len(t, result, 2) // unchanged
	})

	t.Run("triggers compaction on token threshold", func(t *testing.T) {
		config := ContextManagerConfig{
			TokenThreshold:            10,
			OverlapSize:               1,
			PreserveLastN:             1,
			TokenEstimateRatio:        4.0,
			CompactionSummaryTemplate: "{summary}",
		}
		messages := []Message{
			{Role: "user", Content: "This is a long message with many words"},
			{Role: "assistant", Content: "This is a long response with many words"},
			{Role: "user", Content: "Another long message here too"},
		}
		result := applyCompactionStrategy(messages, config)
		require.Len(t, result, 2) // 1 summary + 1 recent
		require.Equal(t, "system", result[0].Role)
		require.Equal(t, "Another long message here too", result[1].Content)
	})

	t.Run("overlap size determines recent messages kept", func(t *testing.T) {
		config := ContextManagerConfig{
			CompactionInterval:        2,
			OverlapSize:               3,
			PreserveLastN:             1,
			TokenEstimateRatio:        4.0,
			CompactionSummaryTemplate: "{summary}",
		}
		messages := []Message{
			{Role: "user", Content: "Msg 1"},
			{Role: "assistant", Content: "Resp 1"},
			{Role: "user", Content: "Msg 2"},
			{Role: "assistant", Content: "Resp 2"},
			{Role: "user", Content: "Msg 3"},
		}
		result := applyCompactionStrategy(messages, config)
		// overlap_size=3, so keep last 3: Resp 2, Msg 3 + summary of earlier
		require.Len(t, result, 4) // 1 summary + 3 overlap
		require.Equal(t, "system", result[0].Role)
	})

	t.Run("empty messages returns empty", func(t *testing.T) {
		config := ContextManagerConfig{
			CompactionInterval: 3,
		}
		result := applyCompactionStrategy([]Message{}, config)
		require.Len(t, result, 0)
	})

	t.Run("not enough messages to compact returns original", func(t *testing.T) {
		config := ContextManagerConfig{
			CompactionInterval: 1,
			OverlapSize:        5, // overlap larger than message count
			PreserveLastN:      5,
		}
		messages := []Message{
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
		}
		result := applyCompactionStrategy(messages, config)
		require.Len(t, result, 2) // unchanged, can't compact
	})
}

func TestManageContextWithCompaction(t *testing.T) {
	t.Run("compaction strategy with system message", func(t *testing.T) {
		config := ContextManagerConfig{
			PreserveSystemMessage:     true,
			SummarizeStrategy:         "compaction",
			CompactionInterval:        2,
			OverlapSize:               1,
			PreserveLastN:             1,
			TokenEstimateRatio:        4.0,
			CompactionSummaryTemplate: "[Summary]\n{summary}",
		}
		messages := []Message{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "Message 1"},
			{Role: "assistant", Content: "Response 1"},
			{Role: "user", Content: "Message 2"},
			{Role: "assistant", Content: "Response 2"},
		}
		result := manageContext(messages, config)

		// Should have: system + summary + 1 recent
		require.True(t, len(result) >= 2)
		require.Equal(t, "system", result[0].Role)
		require.Equal(t, "You are helpful", result[0].Content) // preserved original system
		// Last message should be the most recent
		require.Equal(t, "Response 2", result[len(result)-1].Content)
	})

	t.Run("compaction with no limits set but strategy is compaction", func(t *testing.T) {
		config := ContextManagerConfig{
			PreserveSystemMessage:     true,
			SummarizeStrategy:         "compaction",
			CompactionInterval:        2,
			OverlapSize:               1,
			PreserveLastN:             1,
			TokenEstimateRatio:        4.0,
			CompactionSummaryTemplate: "{summary}",
		}
		messages := []Message{
			{Role: "user", Content: "Msg 1"},
			{Role: "assistant", Content: "Resp 1"},
			{Role: "user", Content: "Msg 2"},
		}
		result := manageContext(messages, config)
		// Even with max_messages=0 and max_tokens=0, compaction strategy should work
		// because compaction_interval=2 and we have 2 user turns
		require.True(t, len(result) < len(messages))
	})
}

func TestBuildScopeKey(t *testing.T) {
	t.Run("builds session scope key", func(t *testing.T) {
		key := buildScopeKey("session", "data")
		require.Equal(t, "session:data", key)
	})

	t.Run("builds user scope key", func(t *testing.T) {
		key := buildScopeKey("user", "preferences")
		require.Equal(t, "user:preferences", key)
	})

	t.Run("builds app scope key", func(t *testing.T) {
		key := buildScopeKey("app", "config")
		require.Equal(t, "app:config", key)
	})

	t.Run("defaults to session when empty", func(t *testing.T) {
		key := buildScopeKey("", "data")
		require.Equal(t, "session:data", key)
	})
}

func TestOnHttpRequestBodyCompaction(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("compaction strategy reduces messages", func(t *testing.T) {
			host, status := test.NewTestHost(compactionConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "example.com"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
			})

			body := `{
				"model": "gpt-4",
				"messages": [
					{"role": "system", "content": "You are helpful"},
					{"role": "user", "content": "Message 1"},
					{"role": "assistant", "content": "Response 1"},
					{"role": "user", "content": "Message 2"},
					{"role": "assistant", "content": "Response 2"},
					{"role": "user", "content": "Message 3"},
					{"role": "assistant", "content": "Response 3"},
					{"role": "user", "content": "Current question"}
				]
			}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)

			modifiedBody := host.GetRequestBody()
			require.NotEmpty(t, modifiedBody)

			messages := gjson.GetBytes(modifiedBody, "messages")
			require.True(t, messages.Exists())

			// With compaction (interval=3, overlap=2), messages should be compressed
			msgArray := messages.Array()
			require.Less(t, len(msgArray), 9) // should be fewer than original 9 messages

			// First message should still be system
			require.Equal(t, "system", msgArray[0].Get("role").String())
			require.Equal(t, "You are helpful", msgArray[0].Get("content").String())

			// Last message should be the most recent user message
			lastMsg := msgArray[len(msgArray)-1]
			require.Equal(t, "Current question", lastMsg.Get("content").String())
		})
	})
}

// --- Tests for newly added Google ADK-inspired features ---

// Test configurations for new features
var turnPairConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"max_messages":            4,
		"preserve_system_message": true,
		"preserve_last_n":         2,
		"summarize_strategy":      "sliding_window",
		"preserve_turn_pairs":     true,
	})
	return data
}()

var pinnedRolesConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"max_messages":            3,
		"preserve_system_message": true,
		"preserve_last_n":         1,
		"summarize_strategy":      "sliding_window",
		"pinned_message_roles":    []string{"tool", "function"},
	})
	return data
}()

var cacheConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"cache_system_prompt": true,
		"cache_min_tokens":    5,
	})
	return data
}()

var trackTokenConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"track_token_usage": true,
	})
	return data
}()

func TestParseConfigNewFeatures(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("parse turn pair config", func(t *testing.T) {
			host, status := test.NewTestHost(turnPairConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			ctxConfig := config.(*ContextManagerConfig)
			require.True(t, ctxConfig.PreserveTurnPairs)
			require.Equal(t, 4, ctxConfig.MaxMessages)
		})

		t.Run("parse pinned roles config", func(t *testing.T) {
			host, status := test.NewTestHost(pinnedRolesConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			ctxConfig := config.(*ContextManagerConfig)
			require.Equal(t, []string{"tool", "function"}, ctxConfig.PinnedMessageRoles)
		})

		t.Run("parse cache config", func(t *testing.T) {
			host, status := test.NewTestHost(cacheConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			ctxConfig := config.(*ContextManagerConfig)
			require.True(t, ctxConfig.CacheSystemPrompt)
			require.Equal(t, 5, ctxConfig.CacheMinTokens)
		})

		t.Run("parse track token config", func(t *testing.T) {
			host, status := test.NewTestHost(trackTokenConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			ctxConfig := config.(*ContextManagerConfig)
			require.True(t, ctxConfig.TrackTokenUsage)
		})

		t.Run("defaults for new fields in empty config", func(t *testing.T) {
			host, status := test.NewTestHost(emptyContextConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			ctxConfig := config.(*ContextManagerConfig)
			require.False(t, ctxConfig.PreserveTurnPairs)
			require.Nil(t, ctxConfig.PinnedMessageRoles)
			require.False(t, ctxConfig.CacheSystemPrompt)
			require.Equal(t, 0, ctxConfig.CacheMinTokens)
			require.False(t, ctxConfig.TrackTokenUsage)
		})
	})
}

func TestExtractPinnedMessages(t *testing.T) {
	t.Run("extracts tool messages as pinned", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Call the search tool"},
			{Role: "assistant", Content: "Calling search..."},
			{Role: "tool", Content: "Search result: found 5 items"},
			{Role: "user", Content: "Great, next question"},
			{Role: "assistant", Content: "Sure!"},
		}
		pinned, unpinned := extractPinnedMessages(messages, []string{"tool"})
		require.Len(t, pinned, 1)
		require.Equal(t, "tool", pinned[0].Role)
		require.Len(t, unpinned, 4)
	})

	t.Run("extracts multiple pinned roles", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Use tools"},
			{Role: "tool", Content: "Tool result"},
			{Role: "function", Content: "Function result"},
			{Role: "assistant", Content: "Done"},
		}
		pinned, unpinned := extractPinnedMessages(messages, []string{"tool", "function"})
		require.Len(t, pinned, 2)
		require.Len(t, unpinned, 2)
	})

	t.Run("no pinned roles returns all as unpinned", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
		}
		pinned, unpinned := extractPinnedMessages(messages, []string{"tool"})
		require.Len(t, pinned, 0)
		require.Len(t, unpinned, 2)
	})

	t.Run("empty messages", func(t *testing.T) {
		pinned, unpinned := extractPinnedMessages([]Message{}, []string{"tool"})
		require.Len(t, pinned, 0)
		require.Len(t, unpinned, 0)
	})
}

func TestEnsureTurnPairIntegrity(t *testing.T) {
	t.Run("keeps complete user-assistant pairs", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
			{Role: "user", Content: "How are you?"},
			{Role: "assistant", Content: "Fine!"},
		}
		result := ensureTurnPairIntegrity(messages)
		require.Len(t, result, 4)
	})

	t.Run("removes orphaned assistant at start", func(t *testing.T) {
		messages := []Message{
			{Role: "assistant", Content: "Orphaned response"},
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
		}
		result := ensureTurnPairIntegrity(messages)
		require.Len(t, result, 2)
		require.Equal(t, "user", result[0].Role)
		require.Equal(t, "assistant", result[1].Role)
	})

	t.Run("keeps trailing user message (latest query)", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
			{Role: "user", Content: "Latest question"},
		}
		result := ensureTurnPairIntegrity(messages)
		require.Len(t, result, 3)
		require.Equal(t, "Latest question", result[2].Content)
	})

	t.Run("preserves tool messages", func(t *testing.T) {
		messages := []Message{
			{Role: "user", Content: "Call tool"},
			{Role: "assistant", Content: "Calling..."},
			{Role: "tool", Content: "Tool result"},
			{Role: "user", Content: "Next"},
		}
		result := ensureTurnPairIntegrity(messages)
		require.Len(t, result, 4)
		require.Equal(t, "tool", result[2].Role)
	})

	t.Run("preserves system summary messages", func(t *testing.T) {
		messages := []Message{
			{Role: "system", Content: "[Summary] Previous context..."},
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi!"},
		}
		result := ensureTurnPairIntegrity(messages)
		require.Len(t, result, 3)
		require.Equal(t, "system", result[0].Role)
	})

	t.Run("empty messages returns empty", func(t *testing.T) {
		result := ensureTurnPairIntegrity([]Message{})
		require.Len(t, result, 0)
	})
}

func TestIsToolMessage(t *testing.T) {
	t.Run("identifies tool role", func(t *testing.T) {
		require.True(t, isToolMessage(Message{Role: "tool", Content: "result"}))
	})

	t.Run("identifies function role", func(t *testing.T) {
		require.True(t, isToolMessage(Message{Role: "function", Content: "result"}))
	})

	t.Run("identifies tool_calls field", func(t *testing.T) {
		require.True(t, isToolMessage(Message{Role: "assistant", ToolCalls: []interface{}{}}))
	})

	t.Run("identifies tool_call_id field", func(t *testing.T) {
		require.True(t, isToolMessage(Message{Role: "tool", ToolCallID: "call_123"}))
	})

	t.Run("identifies function_call field", func(t *testing.T) {
		require.True(t, isToolMessage(Message{Role: "assistant", FunctionCall: map[string]interface{}{"name": "fn"}}))
	})

	t.Run("regular user message is not tool", func(t *testing.T) {
		require.False(t, isToolMessage(Message{Role: "user", Content: "Hello"}))
	})

	t.Run("regular assistant message is not tool", func(t *testing.T) {
		require.False(t, isToolMessage(Message{Role: "assistant", Content: "Hi!"}))
	})
}

func TestManageContextWithPinnedRoles(t *testing.T) {
	t.Run("preserves pinned tool messages during sliding window", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:           3,
			PreserveSystemMessage: true,
			PreserveLastN:         1,
			SummarizeStrategy:     "sliding_window",
			PinnedMessageRoles:    []string{"tool"},
			TokenEstimateRatio:    4.0,
		}
		messages := []Message{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "Old message 1"},
			{Role: "assistant", Content: "Old response 1"},
			{Role: "tool", Content: "Important tool result"},
			{Role: "user", Content: "Message 2"},
			{Role: "assistant", Content: "Response 2"},
			{Role: "user", Content: "Latest question"},
		}
		result := manageContext(messages, config)

		// Should contain: system + pinned tool message + some recent messages
		hasSystem := false
		hasTool := false
		for _, msg := range result {
			if msg.Role == "system" && msg.Content == "You are helpful" {
				hasSystem = true
			}
			if msg.Role == "tool" {
				hasTool = true
			}
		}
		require.True(t, hasSystem, "system message should be preserved")
		require.True(t, hasTool, "pinned tool message should be preserved")
	})
}

func TestManageContextWithTurnPairs(t *testing.T) {
	t.Run("sliding window with turn pair integrity", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:           3,
			PreserveSystemMessage: true,
			PreserveLastN:         1,
			SummarizeStrategy:     "sliding_window",
			PreserveTurnPairs:     true,
			TokenEstimateRatio:    4.0,
		}
		messages := []Message{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "Message 1"},
			{Role: "assistant", Content: "Response 1"},
			{Role: "user", Content: "Message 2"},
			{Role: "assistant", Content: "Response 2"},
			{Role: "user", Content: "Latest question"},
		}
		result := manageContext(messages, config)

		// After turn-pair integrity, no orphaned assistants should remain
		for i, msg := range result {
			if msg.Role == "assistant" {
				// Must be preceded by a user message (or system/tool)
				require.True(t, i > 0, "assistant should not be first")
				prevRole := result[i-1].Role
				require.True(t, prevRole == "user" || prevRole == "system" || prevRole == "tool",
					"assistant should follow user/system/tool, got: %s", prevRole)
			}
		}
	})
}

func TestToolMessageHandling(t *testing.T) {
	t.Run("preserves tool_calls and tool_call_id in messages", func(t *testing.T) {
		msg := Message{
			Role:       "assistant",
			Content:    "",
			ToolCalls:  []interface{}{map[string]interface{}{"id": "call_1", "type": "function"}},
			ToolCallID: "",
		}
		require.True(t, isToolMessage(msg))

		toolResult := Message{
			Role:       "tool",
			Content:    "result data",
			ToolCallID: "call_1",
		}
		require.True(t, isToolMessage(toolResult))
	})

	t.Run("tool messages survive context management", func(t *testing.T) {
		config := ContextManagerConfig{
			MaxMessages:           0,
			MaxTokens:             0,
			PreserveSystemMessage: true,
			TokenEstimateRatio:    4.0,
		}
		messages := []Message{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "Call search"},
			{Role: "assistant", Content: ""},
			{Role: "tool", Content: "Search results here", ToolCallID: "call_1"},
			{Role: "assistant", Content: "Based on the search..."},
			{Role: "user", Content: "Thanks"},
		}
		result := manageContext(messages, config)
		// No limits set, all messages should be preserved
		require.Len(t, result, 6)
	})
}
