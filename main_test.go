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
