package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// The console page saves checkRequest/checkResponse + a string array of built-in rule
// names + customRules. This test guards the compatibility layer against regression.
func TestParseConfigPageSchema(t *testing.T) {
	raw := `{"checkRequest":true,"checkResponse":false,"rules":["email","phone","idcard","creditcard","ssn","ipv4","apikey"],"customRules":[{"name":"custom_phone","regex":"\\d{3}-\\d{4}-\\d{4}","replaceValue":"***-****-****"}]}`
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(raw), cfg))
	require.True(t, cfg.ProtectRequest)
	require.False(t, cfg.ProtectResponse)

	names := make(map[string]PIIRule, len(cfg.Rules))
	for _, r := range cfg.Rules {
		names[r.Name] = r
	}
	// Every short page name must resolve to its built-in rule.
	for _, want := range []string{"email", "phone_cn", "id_card_cn", "credit_card", "ssn_us", "ipv4", "generic_secret_assignment"} {
		require.Contains(t, names, want)
	}
	// Secret/code rules are not exposed on the page; IR-023 protection must stay on.
	require.Contains(t, names, "aws_access_key")
	require.Contains(t, names, "code_snippet")
	// Page custom rules must be compiled and default to mask.
	require.Contains(t, names, "custom_phone")
	require.Equal(t, "mask", names["custom_phone"].Action)
	for _, r := range cfg.Rules {
		require.NotNil(t, r.compiled, r.Name)
	}
}

func TestParseConfigPageSchemaSubset(t *testing.T) {
	raw := `{"checkRequest":true,"rules":["email"]}`
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(raw), cfg))
	names := make(map[string]bool, len(cfg.Rules))
	for _, r := range cfg.Rules {
		names[r.Name] = true
	}
	require.True(t, names["email"])
	require.False(t, names["phone_cn"])
	require.True(t, names["aws_access_key"])
}

func TestParseConfigSpecSchemaStillWorks(t *testing.T) {
	raw := `{"protect_request":false,"protect_response":true,"rules":[{"name":"custom","pattern":"FOO","replacement":"BAR"}]}`
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(raw), cfg))
	require.False(t, cfg.ProtectRequest)
	require.True(t, cfg.ProtectResponse)
	require.Len(t, cfg.Rules, 1)
	require.Equal(t, "custom", cfg.Rules[0].Name)
	require.Equal(t, "BAR", cfg.Rules[0].Replacement)
}

func TestParseConfigEmptyRulesUsesAllDefaults(t *testing.T) {
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(`{}`), cfg))
	require.Len(t, cfg.Rules, len(defaultAllRules()))
}

func TestParseConfigUnknownPageRuleName(t *testing.T) {
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(`{"rules":["not_a_builtin"]}`), cfg))
	require.NotEmpty(t, cfg.Rules)
	for _, r := range cfg.Rules {
		require.NotEqual(t, "pii", r.Category)
	}
}
