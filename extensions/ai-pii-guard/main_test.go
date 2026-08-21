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
	"testing"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/test"
	"github.com/stretchr/testify/require"
)

// Test configuration with custom rules
var customRulesConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"rules": []map[string]interface{}{
			{
				"name":        "email",
				"pattern":     `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`,
				"replacement": "[EMAIL]",
			},
			{
				"name":        "phone",
				"pattern":     `1[3-9]\d{9}`,
				"replacement": "[PHONE]",
			},
		},
		"protect_request":  true,
		"protect_response": false,
		"log_matches":      true,
	})
	return data
}()

// Test configuration with default rules
var defaultRulesConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{
		"protect_request":  true,
		"protect_response": true,
		"log_matches":      false,
	})
	return data
}()

// Empty configuration (uses defaults)
var emptyPIIConfig = func() json.RawMessage {
	data, _ := json.Marshal(map[string]interface{}{})
	return data
}()

func TestParseConfigPII(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("parse custom rules config", func(t *testing.T) {
			host, status := test.NewTestHost(customRulesConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			piiConfig := config.(*PIIGuardConfig)
			require.Len(t, piiConfig.Rules, 2)
			require.True(t, piiConfig.ProtectRequest)
			require.False(t, piiConfig.ProtectResponse)
			require.True(t, piiConfig.LogMatches)
		})

		t.Run("parse default rules config", func(t *testing.T) {
			host, status := test.NewTestHost(defaultRulesConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			piiConfig := config.(*PIIGuardConfig)
			require.True(t, len(piiConfig.Rules) > 0) // Should have default rules
			require.True(t, piiConfig.ProtectRequest)
			require.True(t, piiConfig.ProtectResponse)
			require.False(t, piiConfig.LogMatches)
		})

		t.Run("parse empty config uses defaults", func(t *testing.T) {
			host, status := test.NewTestHost(emptyPIIConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			config, err := host.GetMatchConfig()
			require.NoError(t, err)
			require.NotNil(t, config)

			piiConfig := config.(*PIIGuardConfig)
			require.True(t, len(piiConfig.Rules) > 0) // Should have default rules
			require.True(t, piiConfig.ProtectRequest)
			require.False(t, piiConfig.ProtectResponse)
		})
	})
}

func TestMaskPII(t *testing.T) {
	// Define rules in order of specificity - longer patterns first
	rules := []PIIRule{
		{
			Name:        "email",
			Pattern:     `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`,
			Replacement: "[EMAIL]",
			compiled:    regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`),
		},
		{
			Name:        "id_card",
			Pattern:     `\d{17}[\dXx]`,
			Replacement: "[ID]",
			compiled:    regexp.MustCompile(`\d{17}[\dXx]`),
		},
		{
			Name:        "phone",
			Pattern:     `\b1[3-9]\d{9}\b`,
			Replacement: "[PHONE]",
			compiled:    regexp.MustCompile(`\b1[3-9]\d{9}\b`),
		},
	}

	t.Run("masks email", func(t *testing.T) {
		input := "Contact me at john.doe@example.com for more info"
		result := maskPII(input, rules, false)
		require.Equal(t, "Contact me at [EMAIL] for more info", result)
	})

	t.Run("masks phone number", func(t *testing.T) {
		input := "My phone is 13812345678"
		result := maskPII(input, rules, false)
		require.Equal(t, "My phone is [PHONE]", result)
	})

	t.Run("masks ID card", func(t *testing.T) {
		input := "ID: 110101199003076519"
		result := maskPII(input, rules, false)
		require.Equal(t, "ID: [ID]", result)
	})

	t.Run("masks multiple PII types separately", func(t *testing.T) {
		// Test each type separately to avoid overlap issues
		emailInput := "Email: test@test.com"
		emailResult := maskPII(emailInput, rules, false)
		require.Equal(t, "Email: [EMAIL]", emailResult)

		phoneInput := "Phone: 13912345678"
		phoneResult := maskPII(phoneInput, rules, false)
		require.Equal(t, "Phone: [PHONE]", phoneResult)
	})

	t.Run("no PII to mask", func(t *testing.T) {
		input := "Hello, how are you today?"
		result := maskPII(input, rules, false)
		require.Equal(t, "Hello, how are you today?", result)
	})

	t.Run("empty text", func(t *testing.T) {
		input := ""
		result := maskPII(input, rules, false)
		require.Equal(t, "", result)
	})

	t.Run("empty rules", func(t *testing.T) {
		input := "test@test.com"
		result := maskPII(input, []PIIRule{}, false)
		require.Equal(t, "test@test.com", result)
	})
}

func TestDefaultPIIRules(t *testing.T) {
	rules := DefaultPIIRules()

	t.Run("has email rule", func(t *testing.T) {
		found := false
		for _, rule := range rules {
			if rule.Name == "email" {
				found = true
				break
			}
		}
		require.True(t, found)
	})

	t.Run("has phone rule", func(t *testing.T) {
		found := false
		for _, rule := range rules {
			if rule.Name == "phone_cn" {
				found = true
				break
			}
		}
		require.True(t, found)
	})

	t.Run("has credit card rule", func(t *testing.T) {
		found := false
		for _, rule := range rules {
			if rule.Name == "credit_card" {
				found = true
				break
			}
		}
		require.True(t, found)
	})
}

func TestItoa(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		require.Equal(t, "0", itoa(0))
	})

	t.Run("positive", func(t *testing.T) {
		require.Equal(t, "123", itoa(123))
	})

	t.Run("negative", func(t *testing.T) {
		require.Equal(t, "-456", itoa(-456))
	})

	t.Run("single digit", func(t *testing.T) {
		require.Equal(t, "7", itoa(7))
	})
}

func TestMaskPIIInMessages(t *testing.T) {
	rules := []PIIRule{
		{
			Name:        "email",
			Pattern:     `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`,
			Replacement: "[EMAIL]",
			compiled:    regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`),
		},
	}

	t.Run("exported function masks PII", func(t *testing.T) {
		input := "Send to user@example.com"
		result := MaskPIIInMessages(input, rules)
		require.Equal(t, "Send to [EMAIL]", result)
	})
}

func TestOnHttpRequestBodyPII(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("masks PII in request body", func(t *testing.T) {
			host, status := test.NewTestHost(customRulesConfig)
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
					{"role": "user", "content": "My email is test@example.com and phone is 13812345678"}
				]
			}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)

			// Get the modified body
			modifiedBody := host.GetRequestBody()
			require.NotEmpty(t, modifiedBody)

			// Verify PII is masked
			require.Contains(t, string(modifiedBody), "[EMAIL]")
			require.Contains(t, string(modifiedBody), "[PHONE]")
			require.NotContains(t, string(modifiedBody), "test@example.com")
			require.NotContains(t, string(modifiedBody), "13812345678")
		})

		t.Run("handles messages without content", func(t *testing.T) {
			host, status := test.NewTestHost(customRulesConfig)
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
					{"role": "user"}
				]
			}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)
		})

		t.Run("handles missing messages field", func(t *testing.T) {
			host, status := test.NewTestHost(customRulesConfig)
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
	})
}

func TestMultipleMessagesPII(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("masks PII in multiple messages", func(t *testing.T) {
			host, status := test.NewTestHost(customRulesConfig)
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
					{"role": "system", "content": "You are a helpful assistant"},
					{"role": "user", "content": "My email is user1@test.com"},
					{"role": "assistant", "content": "Got it!"},
					{"role": "user", "content": "Also call me at 13912345678"}
				]
			}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)

			// Get the modified body
			modifiedBody := host.GetRequestBody()
			require.NotEmpty(t, modifiedBody)

			// Verify PII is masked in both user messages
			require.Contains(t, string(modifiedBody), "[EMAIL]")
			require.Contains(t, string(modifiedBody), "[PHONE]")
			// Original system message should be unchanged
			require.Contains(t, string(modifiedBody), "You are a helpful assistant")
		})
	})
}
