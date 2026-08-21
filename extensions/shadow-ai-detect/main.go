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
		"shadow-ai-detect",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

// CategoryConfig defines a category of AI services to detect
type CategoryConfig struct {
	Name      string   // e.g. "saas_ai"
	Label     string   // e.g. "云端SaaS AI"
	RiskLevel string   // e.g. "high"
	Domains   []string // exact domain matches, e.g. "api.openai.com"
	Suffixes  []string // domain suffix matches, e.g. ".openai.com"
}

// ShadowAiDetectConfig is the plugin configuration
type ShadowAiDetectConfig struct {
	mode           string            // "monitoring" or "enforcement"
	blockedCode    uint32            // HTTP status code for blocking
	blockedMessage string            // response body for blocking
	categories     []CategoryConfig  // AI service categories to detect
	counterMetrics map[string]proxywasm.MetricCounter
}

func parseConfig(json gjson.Result, config *ShadowAiDetectConfig, log log.Log) error {
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

		if len(cc.Domains) > 0 || len(cc.Suffixes) > 0 {
			config.categories = append(config.categories, cc)
		}
	}

	config.counterMetrics = make(map[string]proxywasm.MetricCounter)
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config ShadowAiDetectConfig, log log.Log) types.Action {
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

	if sni == "" && host == "" {
		return types.ActionContinue
	}

	// Match against categories
	for _, cat := range config.categories {
		matched, matchedDomain := matchDomainWithResult(sni, host, cat)
		if matched {
			// Use the matched domain for metric (prefer host over sni)
			domain := matchedDomain
			if domain == "" {
				domain = host
				if domain == "" {
					domain = sni
				}
			}

			// Determine status based on mode: "blocked" in enforcement, "allowed" in monitoring
			status := "allowed"
			if config.mode == "enforcement" {
				status = "blocked"
			}

			// Emit Prometheus metric using "." separator format (same as ai-statistics)
			// so Envoy's Prometheus exporter can convert it to labeled format.
			// Format: shadow_ai_detect.category.{cat}.domain.{domain}.risk.{risk}.status.{status}.requests
			metricName := fmt.Sprintf("shadow_ai_detect.category.%s.domain.%s.risk.%s.status.%s.requests",
				sanitizeMetricValue(cat.Name),
				sanitizeMetricValue(domain),
				sanitizeMetricValue(cat.RiskLevel),
				status,
			)
			config.incrementCounter(metricName, 1)

			log.Infof("shadow-ai-detect: matched category=%s domain=%s risk=%s status=%s host=%s sni=%s",
				cat.Name, domain, cat.RiskLevel, status, host, sni)

			// Block in enforcement mode
			if config.mode == "enforcement" {
				proxywasm.SendHttpResponseWithDetail(config.blockedCode,
					"shadow-ai-detect.blocked", nil, []byte(config.blockedMessage), -1)
				return types.ActionPause
			}

			// In monitoring mode, just continue
			return types.ActionContinue
		}
	}

	return types.ActionContinue
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

func (config *ShadowAiDetectConfig) incrementCounter(metricName string, inc uint64) {
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
