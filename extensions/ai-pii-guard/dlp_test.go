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
	"testing"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/test"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// IR-023 DLP 增强测试：分类分级 / secret 识别 / code 告警 / 动作语义

func compileRules(t *testing.T, rules []PIIRule) []PIIRule {
	t.Helper()
	for i := range rules {
		rules[i].compiled = regexp.MustCompile(rules[i].Pattern)
	}
	return rules
}

func TestDefaultSecretRules(t *testing.T) {
	rules := DefaultSecretRules()

	t.Run("rule inventory", func(t *testing.T) {
		names := map[string]bool{}
		for _, r := range rules {
			names[r.Name] = true
			require.Equal(t, "secret", r.Category, r.Name)
			require.Equal(t, "block", r.Action, r.Name)
		}
		for _, expect := range []string{"aws_access_key", "private_key_block", "github_token", "openai_style_key", "jwt_token", "generic_secret_assignment"} {
			require.True(t, names[expect], expect)
		}
	})

	t.Run("detects aws access key", func(t *testing.T) {
		_, hits := processText("use key AKIAIOSFODNN7EXAMPLE please", compileRules(t, rules), false)
		require.Contains(t, ruleNames(hits), "aws_access_key")
	})

	t.Run("detects private key block", func(t *testing.T) {
		_, hits := processText("-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n", compileRules(t, rules), false)
		require.Contains(t, ruleNames(hits), "private_key_block")
	})

	t.Run("detects github token", func(t *testing.T) {
		_, hits := processText("token ghp_0123456789abcdefghijklmnopqrstuvwxyz leaks", compileRules(t, rules), false)
		require.Contains(t, ruleNames(hits), "github_token")
	})

	t.Run("detects openai style key", func(t *testing.T) {
		_, hits := processText("my key sk-abcdefghijklmnopqrstuvwx", compileRules(t, rules), false)
		require.Contains(t, ruleNames(hits), "openai_style_key")
	})

	t.Run("openai style key no false positive on task-", func(t *testing.T) {
		_, hits := processText("task-12345678901234567890 pending", compileRules(t, rules), false)
		require.NotContains(t, ruleNames(hits), "openai_style_key")
	})

	t.Run("detects jwt token", func(t *testing.T) {
		_, hits := processText("auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", compileRules(t, rules), false)
		require.Contains(t, ruleNames(hits), "jwt_token")
	})

	t.Run("detects generic secret assignment", func(t *testing.T) {
		_, hits := processText(`api_key = "abcd1234efgh5678"`, compileRules(t, rules), false)
		require.Contains(t, ruleNames(hits), "generic_secret_assignment")
	})

	t.Run("benign text no match", func(t *testing.T) {
		_, hits := processText("Hello, how are you today?", compileRules(t, rules), false)
		require.Empty(t, hits)
	})

	t.Run("secret rules do not mask (block action)", func(t *testing.T) {
		text := "use key AKIAIOSFODNN7EXAMPLE please"
		masked, _ := processText(text, compileRules(t, rules), false)
		require.Equal(t, text, masked)
	})
}

func TestDefaultCodeRules(t *testing.T) {
	rules := compileRules(t, DefaultCodeRules())
	require.Len(t, rules, 1)
	require.Equal(t, "code", rules[0].Category)
	require.Equal(t, "alert", rules[0].Action)

	t.Run("detects python snippet", func(t *testing.T) {
		_, hits := processText("here is my code:\ndef connect(db):\n    return db", rules, false)
		require.Contains(t, ruleNames(hits), "code_snippet")
	})

	t.Run("detects go snippet", func(t *testing.T) {
		_, hits := processText("code:\nfunc main() {}\n", rules, false)
		require.Contains(t, ruleNames(hits), "code_snippet")
	})

	t.Run("detects markdown fence", func(t *testing.T) {
		_, hits := processText("see below\n\x60\x60\x60python\nprint(1)\n\x60\x60\x60", rules, false)
		require.Contains(t, ruleNames(hits), "code_snippet")
	})

	t.Run("benign text no match", func(t *testing.T) {
		_, hits := processText("please refactor the login module", rules, false)
		require.Empty(t, hits)
	})

	t.Run("code rules do not mask (alert action)", func(t *testing.T) {
		text := "def connect(db):\n    return db"
		masked, _ := processText(text, rules, false)
		require.Equal(t, text, masked)
	})
}

func TestDefaultPIIRulesClassification(t *testing.T) {
	rules := DefaultPIIRules()
	for _, r := range rules {
		require.Equal(t, "pii", r.Category, r.Name)
		require.Equal(t, "mask", r.Action, r.Name)
		require.Contains(t, []string{"low", "medium", "high", "critical"}, r.Severity, r.Name)
	}
}

func TestRuleActionDefaults(t *testing.T) {
	// 空 Action 归一化为 mask（兼容 v1.0.0 用户自定义规则）
	require.Equal(t, "mask", ruleAction(PIIRule{Name: "x"}))
	require.Equal(t, "pii", ruleCategory(PIIRule{Name: "x"}))
	require.Equal(t, "medium", ruleSeverity(PIIRule{Name: "x"}))
	require.Equal(t, "critical", ruleSeverity(PIIRule{Severity: "critical"}))
}

func TestTopSeverityHit(t *testing.T) {
	hits := []PIIRule{
		{Name: "a", Severity: "medium"},
		{Name: "b", Severity: "critical"},
		{Name: "c", Severity: "high"},
	}
	require.Equal(t, "b", topSeverityHit(hits).Name)
}

func TestEventTypeFor(t *testing.T) {
	require.Equal(t, "secret_exfil", eventTypeFor("secret"))
	require.Equal(t, "code_exfil", eventTypeFor("code"))
	require.Equal(t, "pii_leak", eventTypeFor("pii"))
	require.Equal(t, "pii_leak", eventTypeFor(""))
}

func TestSecurityScore(t *testing.T) {
	require.Equal(t, 90, securityScore("critical"))
	require.Equal(t, 80, securityScore("high"))
	require.Equal(t, 60, securityScore("medium"))
	require.Equal(t, 30, securityScore("low"))
}

func TestParseConfigDLP(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("default config includes secret and code rules", func(t *testing.T) {
			cfg := []byte(`{"protect_request":true}`)
			config := &PIIGuardConfig{}
			require.NoError(t, parseConfig(gjson.Parse(string(cfg)), config))
			categories := map[string]int{}
			for _, r := range config.Rules {
				categories[ruleCategory(r)]++
			}
			require.True(t, categories["pii"] >= 7)
			require.Equal(t, 6, categories["secret"])
			require.Equal(t, 1, categories["code"])
		})

		t.Run("custom rules take full control (no built-in append)", func(t *testing.T) {
			cfg := []byte(`{"rules":[{"name":"email","pattern":"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}","replacement":"[EMAIL]"}]}`)
			config := &PIIGuardConfig{}
			require.NoError(t, parseConfig(gjson.Parse(string(cfg)), config))
			require.Len(t, config.Rules, 1)
			require.Equal(t, "mask", ruleAction(config.Rules[0]))
		})

		t.Run("custom rule with classification fields", func(t *testing.T) {
			cfg := []byte(`{"rules":[{"name":"my_secret","pattern":"XYZ\\d+","replacement":"[R]","category":"secret","severity":"critical","action":"block"}]}`)
			config := &PIIGuardConfig{}
			require.NoError(t, parseConfig(gjson.Parse(string(cfg)), config))
			require.Equal(t, "secret", config.Rules[0].Category)
			require.Equal(t, "critical", config.Rules[0].Severity)
			require.Equal(t, "block", config.Rules[0].Action)
		})

		t.Run("report config parsed", func(t *testing.T) {
			cfg := []byte(`{"report_fqdn":"console.svc","report_port":8080,"report_token":"tk"}`)
			config := &PIIGuardConfig{}
			require.NoError(t, parseConfig(gjson.Parse(string(cfg)), config))
			require.Equal(t, "console.svc", config.ReportFQDN)
			require.Equal(t, int64(8080), config.ReportPort)
			require.Equal(t, "tk", config.ReportToken)
		})
	})
}

func TestOnHttpRequestBodySecretBlock(t *testing.T) {
	test.RunGoTest(t, func(t *testing.T) {
		t.Run("blocks request containing aws key (default rules)", func(t *testing.T) {
			// defaultRulesConfig 无自定义 rules → 内置 secret/code 规则生效
			host, status := test.NewTestHost(defaultRulesConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "demo-llm.local"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
			})

			body := `{"model":"m","messages":[{"role":"user","content":"my key is AKIAIOSFODNN7EXAMPLE"}]}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)
			resp := host.GetLocalResponse()
			require.NotNil(t, resp)
			require.Equal(t, uint32(403), resp.StatusCode)
		})

		t.Run("code snippet passes through with alert (default rules)", func(t *testing.T) {
			host, status := test.NewTestHost(defaultRulesConfig)
			defer host.Reset()
			require.Equal(t, types.OnPluginStartStatusOK, status)

			host.CallOnHttpRequestHeaders([][2]string{
				{":authority", "demo-llm.local"},
				{":path", "/v1/chat/completions"},
				{":method", "POST"},
			})

			body := `{"model":"m","messages":[{"role":"user","content":"check this\ndef connect(db):\n    return db"}]}`
			action := host.CallOnHttpRequestBody([]byte(body))
			require.Equal(t, types.ActionContinue, action)
			require.Nil(t, host.GetLocalResponse())
		})
	})
}
