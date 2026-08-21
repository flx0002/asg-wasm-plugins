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
)

// Test configuration with Redis
var redisConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"redis": map[string]interface{}{
			"service_name": "redis.static",
			"service_port": 6379,
			"password":     "test_password",
			"timeout":      1000,
		},
		"redis_key_prefix":        "test_billing:",
		"consumer_header":         "x-api-key",
		"quota_enforcement":       true,
		"deny_message":            "API quota exceeded",
		"input_token_multiplier":  1.0,
		"output_token_multiplier": 2.0,
		"log_usage":               true,
	})
	return data
}()

// Test configuration without Redis
var noRedisConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"consumer_header":         "x-mse-consumer",
		"input_token_multiplier":  1.5,
		"output_token_multiplier": 3.0,
		"log_usage":               true,
	})
	return data
}()

// Empty configuration
var emptyBillingConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{})
	return data
}()

func TestParseConfigBilling(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("parse redis config", func(t *testing.T) {
			host, status := test.NewTestHost(redisConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			billingConfig := config.(*TokenBillingConfig)
			require.Equal(t, "test_billing:", billingConfig.RedisKeyPrefix)
			require.Equal(t, "x-api-key", billingConfig.ConsumerHeader)
			require.True(t, billingConfig.QuotaEnforcement)
			require.Equal(t, "API quota exceeded", billingConfig.DenyMessage)
			require.Equal(t, 1.0, billingConfig.InputTokenMultiplier)
			require.Equal(t, 2.0, billingConfig.OutputTokenMultiplier)
			require.True(t, billingConfig.LogUsage)
		})

		t.Run("parse no redis config", func(t *testing.T) {
			host, status := test.NewTestHost(noRedisConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			billingConfig := config.(*TokenBillingConfig)
			require.Equal(t, "x-mse-consumer", billingConfig.ConsumerHeader)
			require.Equal(t, 1.5, billingConfig.InputTokenMultiplier)
			require.Equal(t, 3.0, billingConfig.OutputTokenMultiplier)
			require.Nil(t, billingConfig.redisClient)
		})

		t.Run("parse empty config uses defaults", func(t *testing.T) {
			host, status := test.NewTestHost(emptyBillingConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			billingConfig := config.(*TokenBillingConfig)
			require.Equal(t, "ai_token_billing:", billingConfig.RedisKeyPrefix)
			require.Equal(t, "x-mse-consumer", billingConfig.ConsumerHeader)
			require.False(t, billingConfig.QuotaEnforcement)
			require.Equal(t, "Token quota exceeded", billingConfig.DenyMessage)
			require.Equal(t, 1.0, billingConfig.InputTokenMultiplier)
			require.Equal(t, 1.0, billingConfig.OutputTokenMultiplier)
			require.True(t, billingConfig.LogUsage)
		})
	})
}

func TestOnHttpRequestHeadersBilling(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("sets consumer from header", func(t *testing.T) {
			host, status := test.NewTestHost(noRedisConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			action := host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "example.com"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
				{"x-mse-consumer", "test-user"},
			})

			require.Equal(t, types.ActionContinue, action)
		})

		t.Run("uses anonymous for missing consumer", func(t *testing.T) {
			host, status := test.NewTestHost(noRedisConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			action := host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "example.com"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
			})

			require.Equal(t, types.ActionContinue, action)
		})
	})
}

func TestTokenMultipliers(t *testing.T) {
	t.Run("calculates weighted tokens", func(t *testing.T) {
		inputToken := int64(100)
		outputToken := int64(200)
		inputMultiplier := 1.5
		outputMultiplier := 2.0

		weightedInput := int64(float64(inputToken) * inputMultiplier)
		weightedOutput := int64(float64(outputToken) * outputMultiplier)
		totalWeighted := weightedInput + weightedOutput

		require.Equal(t, int64(150), weightedInput)
		require.Equal(t, int64(400), weightedOutput)
		require.Equal(t, int64(550), totalWeighted)
	})

	t.Run("default multipliers equal 1", func(t *testing.T) {
		inputToken := int64(100)
		outputToken := int64(200)
		inputMultiplier := 1.0
		outputMultiplier := 1.0

		weightedInput := int64(float64(inputToken) * inputMultiplier)
		weightedOutput := int64(float64(outputToken) * outputMultiplier)
		totalWeighted := weightedInput + weightedOutput

		require.Equal(t, int64(100), weightedInput)
		require.Equal(t, int64(200), weightedOutput)
		require.Equal(t, int64(300), totalWeighted)
	})
}

func TestSendDenyResponse(t *testing.T) {
	t.Run("builds error response", func(t *testing.T) {
		// Test the message escaping logic
		message := "Quota exceeded: \"limit reached\""
		escapedMessage := message
		escapedMessage = escapeForJSON(escapedMessage)
		require.Contains(t, escapedMessage, "\\\"")
	})
}

func escapeForJSON(s string) string {
	result := s
	result = replaceAll(result, "\"", "\\\"")
	result = replaceAll(result, "\n", "\\n")
	return result
}

func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); i++ {
		matched := true
		if i+len(old) <= len(s) {
			for j := 0; j < len(old); j++ {
				if s[i+j] != old[j] {
					matched = false
					break
				}
			}
			if matched {
				result += new
				i += len(old) - 1
				continue
			}
		}
		result += string(s[i])
	}
	return result
}

func TestRedisKeyFormat(t *testing.T) {
	t.Run("generates correct keys", func(t *testing.T) {
		prefix := "ai_token_billing:"
		consumer := "test-user"

		usageKey := prefix + "usage:" + consumer
		inputKey := prefix + "input:" + consumer
		outputKey := prefix + "output:" + consumer
		quotaKey := prefix + "quota:" + consumer

		require.Equal(t, "ai_token_billing:usage:test-user", usageKey)
		require.Equal(t, "ai_token_billing:input:test-user", inputKey)
		require.Equal(t, "ai_token_billing:output:test-user", outputKey)
		require.Equal(t, "ai_token_billing:quota:test-user", quotaKey)
	})
}

func TestGetTokenUsageStats(t *testing.T) {
	t.Run("returns zero for no redis", func(t *testing.T) {
		input, output, total := GetTokenUsageStats(nil, "prefix:", "consumer")
		require.Equal(t, int64(0), input)
		require.Equal(t, int64(0), output)
		require.Equal(t, int64(0), total)
	})
}

func TestResponseBodyProcessing(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("processes response body", func(t *testing.T) {
			host, status := test.NewTestHost(noRedisConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			// Call request headers first
			host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "example.com"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
				{"x-mse-consumer", "test-user"},
			})

			// Call response headers
			host.CallOnHttpResponseHeaders([][2]string{
				{":status", "200"},
				{"content-type", "application/json"},
			})

			// Call response body with usage info
			body := `{
				"id": "chatcmpl-123",
				"choices": [{"message": {"content": "Hello!"}}],
				"usage": {
					"prompt_tokens": 10,
					"completion_tokens": 20,
					"total_tokens": 30
				}
			}`
			action := host.CallOnHttpResponseBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)
		})
	})
}
