package main

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestMatchPathPattern(t *testing.T) {
	cat := CategoryConfig{
		PathPatterns: []string{"/v1/chat/completions", "/v1/responses", "/v1beta"},
	}
	cases := []struct {
		path string
		want string
	}{
		{"/v1/chat/completions", "/v1/chat/completions"},
		{"/v1/chat/completions?model=gpt-4", "/v1/chat/completions"},
		{"/v1/responses", "/v1/responses"},
		{"/v1beta/models", "/v1beta"},
		{"/v2/completions", ""},
		{"/health", ""},
		{"/v1", ""},
	}
	for _, c := range cases {
		got := matchPathPattern(c.path, cat)
		if got != c.want {
			t.Errorf("matchPathPattern(%q) = %q, want %q", c.path, got, c.want)
		}
	}

	// Empty patterns never match
	if got := matchPathPattern("/v1/chat/completions", CategoryConfig{}); got != "" {
		t.Errorf("empty patterns should not match, got %q", got)
	}
}

func TestMatchDomainWithResult(t *testing.T) {
	cat := CategoryConfig{
		Domains:  []string{"api.openai.com", "chat.openai.com"},
		Suffixes: []string{".openai.com", ".deepseek.com"},
	}
	cases := []struct {
		sni, host string
		wantHit   bool
		wantMatch string
	}{
		{"api.openai.com", "", true, "api.openai.com"},
		{"", "chat.openai.com", true, "chat.openai.com"},
		{"gpt.internal.openai.com", "", true, "gpt.internal.openai.com"},
		{"api.deepseek.com", "", true, "api.deepseek.com"},
		{"evil.com", "api.openai.com", true, "api.openai.com"},
		{"example.com", "", false, ""},
		{"", "", false, ""},
	}
	for _, c := range cases {
		hit, matched := matchDomainWithResult(c.sni, c.host, cat)
		if hit != c.wantHit || matched != c.wantMatch {
			t.Errorf("matchDomainWithResult(%q,%q) = (%v,%q), want (%v,%q)",
				c.sni, c.host, hit, matched, c.wantHit, c.wantMatch)
		}
	}
}

func TestParseConfigFeatures(t *testing.T) {
	cfgJSON := `{
		"mode": "enforcement",
		"enable_path_feature": true,
		"enable_body_feature": false,
		"categories": [{
			"name": "saas_ai",
			"label": "云端SaaS AI",
			"risk_level": "high",
			"domains": ["api.openai.com"],
			"suffixes": [".openai.com"],
			"path_patterns": ["/v1/chat/completions", "/v1/responses"],
			"body_features": ["model", "messages"]
		}]
	}`
	cfg := AiShadowDetectConfig{}
	if err := parseConfig(gjson.Parse(cfgJSON), &cfg, nil); err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	if cfg.mode != "enforcement" {
		t.Errorf("mode = %q, want enforcement", cfg.mode)
	}
	if !cfg.enablePathFeature {
		t.Error("enable_path_feature should be true")
	}
	if cfg.enableBodyFeature {
		t.Error("enable_body_feature should be false")
	}
	if !cfg.enableSseFeature {
		t.Error("enable_sse_feature should default to true")
	}
	if len(cfg.categories) != 1 {
		t.Fatalf("categories = %d, want 1", len(cfg.categories))
	}
	cat := cfg.categories[0]
	if len(cat.PathPatterns) != 2 || cat.PathPatterns[0] != "/v1/chat/completions" {
		t.Errorf("path_patterns = %v", cat.PathPatterns)
	}
	if len(cat.BodyFeatures) != 2 || cat.BodyFeatures[1] != "messages" {
		t.Errorf("body_features = %v", cat.BodyFeatures)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	// Legacy config without new fields: all features enabled by default, parses fine
	cfgJSON := `{
		"mode": "monitoring",
		"categories": [{"name": "saas_ai", "risk_level": "high", "domains": ["api.openai.com"]}]
	}`
	cfg := AiShadowDetectConfig{}
	if err := parseConfig(gjson.Parse(cfgJSON), &cfg, nil); err != nil {
		t.Fatalf("parseConfig legacy error: %v", err)
	}
	if !cfg.enablePathFeature || !cfg.enableBodyFeature || !cfg.enableSseFeature {
		t.Errorf("legacy config should enable all features by default: %+v", cfg)
	}
	if len(cfg.categories) != 1 || len(cfg.categories[0].Domains) != 1 {
		t.Errorf("legacy categories parse failed: %+v", cfg.categories)
	}
}

func TestSanitizeMetricValue(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"saas_ai", "saas_ai"},
		{"api.openai.com", "api_openai_com"},
		{"my-domain.com", "my_domain_com"},
		{"json_body", "json_body"},
	}
	for _, c := range cases {
		if got := sanitizeMetricValue(c.in); got != c.want {
			t.Errorf("sanitizeMetricValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
