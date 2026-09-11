package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
)

func main() {}

func init() {
	wrapper.SetCtx(
		"ai-shadow-detect",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessRequestBody(onHttpRequestBody),
	)
}

// 命中特征类型（IR-001：域名外至少 1 种特征）
const (
	featureDomain    = "domain"     // SNI/Host 域名匹配（原有）
	featurePath      = "path"       // LLM API 特征路径匹配
	featureJsonBody  = "json_body"  // JSON 载荷结构特征（model/messages/prompt 等字段）
	featureDomainSSE = "domain_sse" // 域名命中 + SSE 流式请求（Accept: text/event-stream）
	featurePathSSE   = "path_sse"   // 路径命中 + SSE 流式请求
	acceptSSE        = "text/event-stream"
)

// CategoryConfig defines a category of AI services to detect
type CategoryConfig struct {
	Name         string   // e.g. "saas_ai"
	Label        string   // e.g. "云端SaaS AI"
	RiskLevel    string   // e.g. "high"
	Domains      []string // exact domain matches, e.g. "api.openai.com"
	Suffixes     []string // domain suffix matches, e.g. ".openai.com"
	PathPatterns []string // LLM API path prefixes, e.g. "/v1/chat/completions"
	BodyFeatures []string // JSON body feature fields, e.g. "model", "messages"
}

// AiShadowDetectConfig is the plugin configuration
type AiShadowDetectConfig struct {
	mode              string           // "monitoring" or "enforcement"
	blockedCode       uint32           // HTTP status code for blocking
	blockedMessage    string           // response body for blocking
	enablePathFeature bool             // enable API path feature detection
	enableBodyFeature bool             // enable JSON body feature detection
	enableSseFeature  bool             // enable SSE streaming enhancement
	categories        []CategoryConfig // AI service categories to detect
	trustedHosts      []string         // sai-b16: ASG-managed ingress hosts (exact or ".suffix") exempt from path/body feature detection
	counterMetrics    map[string]proxywasm.MetricCounter
}

// hitResult records a detection hit with its feature type
type hitResult struct {
	category CategoryConfig
	feature  string // one of featureDomain/featurePath/featureJsonBody/featureDomainSSE/featurePathSSE
	domain   string // matched domain (may be empty for path/body hits)
	detail   string // matched value for logging (path or body field)
}

const ctxHitKey = "ai-shadow-hit"

func parseConfig(json gjson.Result, config *AiShadowDetectConfig, log log.Log) error {
	// Parse mode
	config.mode = json.Get("mode").String()
	if config.mode == "" {
		config.mode = "monitoring"
	}

	// Parse blocked code
	code := json.Get("blocked_code").Int()
	if code > 100 && code < 600 {
		config.blockedCode = uint32(code)
	} else {
		config.blockedCode = http.StatusForbidden
	}

	// Parse blocked message
	config.blockedMessage = json.Get("blocked_message").String()
	if config.blockedMessage == "" {
		config.blockedMessage = "Access to unauthorized AI service is blocked"
	}

	// Parse feature switches (all enabled by default)
	config.enablePathFeature = !json.Get("enable_path_feature").Exists() || json.Get("enable_path_feature").Bool()
	config.enableBodyFeature = !json.Get("enable_body_feature").Exists() || json.Get("enable_body_feature").Bool()
	config.enableSseFeature = !json.Get("enable_sse_feature").Exists() || json.Get("enable_sse_feature").Bool()

	// sai-b16: trusted hosts (ASG-managed ingress domains, e.g. ai-route-*.internal).
	// Exact match or ".suffix" suffix match. Absent or empty config = no exemption (previous behavior).
	for _, h := range json.Get("trusted_hosts").Array() {
		host := strings.ToLower(strings.TrimSpace(h.String()))
		if host != "" {
			config.trustedHosts = append(config.trustedHosts, host)
		}
	}

	// Parse categories
	categoriesResult := json.Get("categories")
	if !categoriesResult.Exists() {
		return nil
	}

	for _, cat := range categoriesResult.Array() {
		cc := CategoryConfig{
			Name:      cat.Get("name").String(),
			Label:     cat.Get("label").String(),
			RiskLevel: cat.Get("risk_level").String(),
		}

		for _, d := range cat.Get("domains").Array() {
			domain := strings.ToLower(strings.TrimSpace(d.String()))
			if domain == "" {
				continue
			}
			if strings.HasPrefix(domain, ".") {
				cc.Suffixes = append(cc.Suffixes, domain)
			} else {
				cc.Domains = append(cc.Domains, domain)
			}
		}

		for _, s := range cat.Get("suffixes").Array() {
			suffix := strings.ToLower(strings.TrimSpace(s.String()))
			if suffix != "" {
				cc.Suffixes = append(cc.Suffixes, suffix)
			}
		}

		// Path patterns: normalized to lowercase, keep as-is (prefix match on request path)
		for _, p := range cat.Get("path_patterns").Array() {
			pattern := strings.ToLower(strings.TrimSpace(p.String()))
			if pattern != "" {
				cc.PathPatterns = append(cc.PathPatterns, pattern)
			}
		}

		// Body features: JSON field names to look up in the request body
		for _, f := range cat.Get("body_features").Array() {
			field := strings.TrimSpace(f.String())
			if field != "" {
				cc.BodyFeatures = append(cc.BodyFeatures, field)
			}
		}

		if len(cc.Domains) > 0 || len(cc.Suffixes) > 0 || len(cc.PathPatterns) > 0 || len(cc.BodyFeatures) > 0 {
			config.categories = append(config.categories, cc)
		}
	}

	config.counterMetrics = make(map[string]proxywasm.MetricCounter)
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config AiShadowDetectConfig, log log.Log) types.Action {
	if len(config.categories) == 0 {
		return types.ActionContinue
	}

	// Get SNI
	sni := ""
	if sniBytes, err := proxywasm.GetProperty([]string{"connection", "requested_server_name"}); err == nil {
		sni = strings.ToLower(string(sniBytes))
	}

	// Get Host header
	host := ""
	if h, err := proxywasm.GetHttpRequestHeader(":authority"); err == nil {
		host = strings.ToLower(stripPortFromHost(h))
	}

	// Get request path (:path pseudo header)
	path := ""
	if p, err := proxywasm.GetHttpRequestHeader(":path"); err == nil {
		path = strings.ToLower(p)
		if i := strings.Index(path, "?"); i != -1 {
			path = path[:i]
		}
	}

	// Get Accept header for SSE streaming enhancement
	accept := ""
	if a, err := proxywasm.GetHttpRequestHeader("accept"); err == nil {
		accept = strings.ToLower(a)
	}
	wantsSSE := config.enableSseFeature && strings.Contains(accept, acceptSSE)

	if sni == "" && host == "" && path == "" {
		return types.ActionContinue
	}

	// Stage 1: domain match (existing behavior)
	for _, cat := range config.categories {
		matched, matchedDomain := matchDomainWithResult(sni, host, cat)
		if matched {
			feature := featureDomain
			if wantsSSE {
				feature = featureDomainSSE
			}
			return reportAndBlock(ctx, config, cat, feature, matchedDomain, matchedDomain)
		}
	}

	// sai-b16: trusted host exemption (after domain stage, before content features).
	// ASG-managed ingress hosts (ai-route-*.internal, demo-llm.local, ...) carry
	// legitimate AI-gateway traffic whose path/body naturally match content features.
	if isTrustedHost(host, config) {
		return types.ActionContinue
	}

	// Stage 2: API path feature (IR-001 non-domain feature)
	if config.enablePathFeature && path != "" {
		for _, cat := range config.categories {
			if matchedPattern := matchPathPattern(path, cat); matchedPattern != "" {
				feature := featurePath
				if wantsSSE {
					feature = featurePathSSE
				}
				return reportAndBlock(ctx, config, cat, feature, matchedPattern, path)
			}
		}
	}

	// Stage 3: JSON body feature is checked in onHttpRequestBody (needs body)
	// Mark whether body detection is needed via context for the body callback.
	if config.enableBodyFeature {
		for _, cat := range config.categories {
			if len(cat.BodyFeatures) > 0 {
				ctx.SetContext(ctxHitKey, "pending")
				return types.ActionContinue
			}
		}
	}

	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config AiShadowDetectConfig, body []byte) types.Action {
	// Only run when headers stage did not hit (checked via context marker)
	marker := ctx.GetContext(ctxHitKey)
	if marker != "pending" {
		return types.ActionContinue
	}
	if len(body) == 0 || !config.enableBodyFeature {
		return types.ActionContinue
	}

	// JSON body feature: look up configured fields (gjson path semantics)
	for _, cat := range config.categories {
		if len(cat.BodyFeatures) == 0 {
			continue
		}
		for _, field := range cat.BodyFeatures {
			// gjson field lookup: top-level or nested (e.g. "model", "messages", "input.prompt")
			if gjson.GetBytes(body, field).Exists() {
				return reportAndBlock(ctx, config, cat, featureJsonBody, field, string(body))
			}
		}
	}

	return types.ActionContinue
}

// reportAndBlock emits the detection metric + log and blocks in enforcement mode.
// Monitoring mode always continues; the ctx hit marker prevents duplicate body detection.
func reportAndBlock(ctx wrapper.HttpContext, config AiShadowDetectConfig, cat CategoryConfig,
	feature, domain, detail string) types.Action {

	// Mark hit so the body callback skips duplicate detection
	ctx.SetContext(ctxHitKey, "hit")

	// Determine status based on mode: "blocked" in enforcement, "allowed" in monitoring
	status := "allowed"
	if config.mode == "enforcement" {
		status = "blocked"
	}

	// Emit Prometheus metric using "." separator format (same as ai-statistics)
	// so Envoy's Prometheus exporter can convert it to labeled format.
	// Domain hits keep the legacy format; feature hits use the feature-dimension format.
	var metricName string
	switch feature {
	case featureDomain, featureDomainSSE:
		metricName = fmt.Sprintf("ai_shadow_detect.category.%s.domain.%s.risk.%s.status.%s.requests",
			sanitizeMetricValue(cat.Name),
			sanitizeMetricValue(domain),
			sanitizeMetricValue(cat.RiskLevel),
			status,
		)
	default:
		metricName = fmt.Sprintf("ai_shadow_detect.category.%s.feature.%s.risk.%s.status.%s.requests",
			sanitizeMetricValue(cat.Name),
			sanitizeMetricValue(feature),
			sanitizeMetricValue(cat.RiskLevel),
			status,
		)
	}
	config.incrementCounter(metricName, 1)

	log.Infof("ai-shadow-detect: matched category=%s feature=%s domain=%s risk=%s status=%s detail=%s",
		cat.Name, feature, domain, cat.RiskLevel, status, detail)

	// Block in enforcement mode
	if config.mode == "enforcement" {
		proxywasm.SendHttpResponseWithDetail(config.blockedCode,
			"ai-shadow-detect.blocked", nil, []byte(config.blockedMessage), -1)
		return types.ActionPause
	}

	return types.ActionContinue
}

// isTrustedHost reports whether host is an ASG-managed ingress host (exact or ".suffix" match).
func isTrustedHost(host string, config AiShadowDetectConfig) bool {
	if host == "" || len(config.trustedHosts) == 0 {
		return false
	}
	for _, t := range config.trustedHosts {
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, ".") {
			if strings.HasSuffix(host, t) {
				return true
			}
		} else if host == t {
			return true
		}
	}
	return false
}

// matchPathPattern checks if the request path starts with any configured LLM API path pattern
func matchPathPattern(path string, cat CategoryConfig) string {
	if len(cat.PathPatterns) == 0 {
		return ""
	}
	for _, pattern := range cat.PathPatterns {
		if strings.HasPrefix(path, pattern) {
			return pattern
		}
	}
	return ""
}

// matchDomainWithResult checks if sni or host matches the category, and returns the matched domain
func matchDomainWithResult(sni, host string, cat CategoryConfig) (bool, string) {
	for _, target := range []string{sni, host} {
		if target == "" {
			continue
		}
		for _, domain := range cat.Domains {
			if target == domain {
				return true, target
			}
		}
		for _, suffix := range cat.Suffixes {
			if strings.HasSuffix(target, suffix) {
				return true, target
			}
		}
	}
	return false, ""
}

func (config *AiShadowDetectConfig) incrementCounter(metricName string, inc uint64) {
	if inc == 0 {
		return
	}
	counter, ok := config.counterMetrics[metricName]
	if !ok {
		counter = proxywasm.DefineCounterMetric(metricName)
		config.counterMetrics[metricName] = counter
	}
	counter.Increment(inc)
}

// sanitizeMetricValue replaces characters that are invalid in Prometheus metric names
func sanitizeMetricValue(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

func stripPortFromHost(requestHost string) string {
	portStart := strings.LastIndex(requestHost, ":")
	if portStart != -1 {
		v6EndIndex := strings.LastIndex(requestHost, "]")
		if v6EndIndex == -1 || v6EndIndex < portStart {
			if portStart+1 <= len(requestHost) {
				return requestHost[:portStart]
			}
		}
	}
	return requestHost
}
