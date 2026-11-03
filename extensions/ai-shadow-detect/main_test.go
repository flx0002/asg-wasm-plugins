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

func TestNormalizeAuthorizedDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Example.COM", "example.com"},
		{"  demo-llm.local  ", "demo-llm.local"},
		{"*.example.com", "example.com"},
		{".example.com", "example.com"},
		{"*.EXAMPLE.com", "example.com"},
		{"example.com.", "example.com"},
		{"example.com..", "example.com"},
		{"127.0.0.1", "127.0.0.1"},
		{"", ""},
		{"...", ""},
	}
	for _, c := range cases {
		if got := normalizeAuthorizedDomain(c.in); got != c.want {
			t.Errorf("normalizeAuthorizedDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsDomainAuthorized(t *testing.T) {
	authorized := []string{"abc.com", "demo-llm.local", "deepseek.com", "127.0.0.1"}
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},           // IP 精确命中
		{"demo-llm.local", true},      // 精确命中
		{"deepseek.com.", true},       // 尾点 FQDN 写法归一化后命中（与界面标记不分裂）
		{"deepseek.com", true},        // 精确命中
		{"www.deepseek.com", true},    // 子域命中
		{"api.deepseek.com", true},    // 子域命中
		{"xabc.com", false},           // 只是后缀沾边，不是子域
		{"evil-demo-llm.local", false},
		{"127.0.0.1.evil.com", false}, // IP 后面接尾缀不覆盖
		{"api.openai.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isDomainAuthorized(c.host, authorized); got != c.want {
			t.Errorf("isDomainAuthorized(%q) = %v, want %v", c.host, got, c.want)
		}
	}

	// 空名单永不授权
	if isDomainAuthorized("example.com", nil) {
		t.Error("empty list should not authorize anything")
	}

	// *.example.com 条目归一化后覆盖子域（与 Console 口径一致）
	if !isDomainAuthorized("api.example.com", []string{"*.example.com"}) {
		t.Error("*.example.com entry should cover api.example.com")
	}

	// 名单侧条目大小写/空白不影响判定（parseConfig 归一化后的二次防御）
	if !isDomainAuthorized("chat.example.com", []string{" Example.COM "}) {
		t.Error("entry normalization should be applied at match time too")
	}
}

func TestParseConfigAuthorizedDomains(t *testing.T) {
	cfgJSON := `{
		"mode": "monitoring",
		"authorized_domains": ["*.Example.COM", " demo-llm.local ", "", ".", "127.0.0.1"],
		"categories": [{"name": "saas_ai", "risk_level": "high", "domains": ["api.openai.com"]}]
	}`
	cfg := AiShadowDetectConfig{}
	if err := parseConfig(gjson.Parse(cfgJSON), &cfg, nil); err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}
	want := []string{"example.com", "demo-llm.local", "127.0.0.1"}
	if len(cfg.authorizedDomains) != len(want) {
		t.Fatalf("authorizedDomains = %v, want %v", cfg.authorizedDomains, want)
	}
	for i, w := range want {
		if cfg.authorizedDomains[i] != w {
			t.Errorf("authorizedDomains[%d] = %q, want %q", i, cfg.authorizedDomains[i], w)
		}
	}
}
