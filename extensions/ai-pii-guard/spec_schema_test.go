package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// spec.yaml contract: protect_request/protect_response/log_matches booleans plus a rules
// object array with required name/pattern. Empty rules fall back to all built-in rules
// (PII mask + secret block + code alert, IR-023).
func TestParseConfigSpecSchema(t *testing.T) {
	raw := `{"protect_request":true,"protect_response":true,"log_matches":false,"rules":[{"name":"custom_email","pattern":"\\bCUSTOM@[A-Za-z.]+\\b","replacement":"[CUSTOM_REDACTED]","category":"pii","severity":"high","action":"mask"}]}`
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(raw), cfg))
	require.True(t, cfg.ProtectRequest)
	require.True(t, cfg.ProtectResponse)
	require.False(t, cfg.LogMatches)
	require.Len(t, cfg.Rules, 1)
	require.Equal(t, "custom_email", cfg.Rules[0].Name)
	require.Equal(t, "[CUSTOM_REDACTED]", cfg.Rules[0].Replacement)
	require.Equal(t, "pii", cfg.Rules[0].Category)
	require.Equal(t, "high", cfg.Rules[0].Severity)
	require.Equal(t, "mask", cfg.Rules[0].Action)
	require.NotNil(t, cfg.Rules[0].compiled)
}

func TestParseConfigEmptyRulesUsesAllDefaults(t *testing.T) {
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(`{}`), cfg))
	require.True(t, cfg.ProtectRequest)
	require.False(t, cfg.ProtectResponse)
	require.True(t, cfg.LogMatches)
	// PII(7) + secret(6) + code(1) = 14 built-in rules
	require.Len(t, cfg.Rules, 14)
	names := map[string]bool{}
	for _, r := range cfg.Rules {
		names[r.Name] = true
	}
	for _, want := range []string{"email", "phone_cn", "id_card_cn", "credit_card", "ssn_us", "ipv4", "aws_access_key", "github_token", "code_snippet"} {
		require.True(t, names[want], want)
	}
}

func TestParseConfigPageStringRulesNoLongerSupported(t *testing.T) {
	// Page writes string array only in the obsolete schema; pure upstream parse skips these
	// because they have no `pattern`. This test documents that the compatibility layer is gone
	// (the console page now writes object arrays).
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(`{"rules":["email","phone"]}`), cfg))
	require.Empty(t, cfg.Rules)
}

func TestParseConfigMissingPatternSkipped(t *testing.T) {
	raw := `{"rules":[{"name":"no_pattern","replacement":"X"},{"name":"valid","pattern":"FOO","replacement":"BAR"}]}`
	cfg := &PIIGuardConfig{}
	require.NoError(t, parseConfig(gjson.Parse(raw), cfg))
	require.Len(t, cfg.Rules, 1)
	require.Equal(t, "valid", cfg.Rules[0].Name)
}
