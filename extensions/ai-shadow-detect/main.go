package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

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

// detect-events 的 detectType 取值（Console 侧原样存储、原样展示）
const (
	detectTypeAccess       = "gateway_ai_access"           // 域名/路径/载荷维度命中
	detectTypeUnauthorized = "gateway_unauthorized_access" // AI 路由上的未认证访问
)

// 默认上报目标：集群内 Console（与 key-auth 的 sai-b15 保持一致）
const (
	defaultReportFQDN = "higress-console.higress-system.svc.cluster.local"
	defaultReportPort = 8080
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

	// sai-b17: detect-events 上报。页面（「检测到的AI服务访问」/KPI/趋势）读的是
	// ai_shadow_detect_event 表，只打 Prometheus 指标不会出现在页面上，故必须逐条上报。
	reportFQDN  string
	reportPort  int64
	reportToken string

	// sai-b18: 认证维度检测。trusted_hosts 覆盖的 ASG 托管 AI 路由上，
	// 没有 x-mse-consumer（key-auth 已认证标识）的访问视为未认证影子 AI。
	enableAuthzFeature bool
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

	// sai-b17: detect-events 上报目标。默认指向集群内 Console；
	// report_token 必须与 Console 的 collector token 一致，否则上报被拒。
	config.reportFQDN = strings.TrimSpace(json.Get("report_fqdn").String())
	if config.reportFQDN == "" {
		config.reportFQDN = defaultReportFQDN
	}
	config.reportPort = json.Get("report_port").Int()
	if config.reportPort <= 0 {
		config.reportPort = defaultReportPort
	}
	config.reportToken = json.Get("report_token").String()

	// sai-b18: 认证维度开关，默认开启；现场可用 enable_authz_feature=false 单独关闭。
	config.enableAuthzFeature = !json.Get("enable_authz_feature").Exists() || json.Get("enable_authz_feature").Bool()

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
		// 认证维度（sai-b18）同样依赖 categories 做 path 门禁，没有分类就无从判定
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
			return reportAndBlock(ctx, config, cat, host, feature, matchedDomain, matchedDomain)
		}
	}

	// sai-b16: trusted host exemption (after domain stage, before content features).
	// ASG-managed ingress hosts (ai-route-*.internal, demo-llm.local, ...) carry
	// legitimate AI-gateway traffic whose path/body naturally match content features.
	//
	// sai-b18: 认证维度在豁免之前插入。trusted_hosts 覆盖的正是 ASG 托管的 AI 路由，
	// 这类路由上 key-auth 认证成功才会写入 x-mse-consumer；没有该头说明这次访问
	// 未经认证，属于影子 AI。这里只上报不阻断：认证拒绝由 key-auth（AUTHN 阶段）
	// 负责，插件处在 AUTHZ 阶段，只能看到已经被放行的请求，重复阻断会掩盖真实原因。
	// 用 path 特征作为「确实是一次 AI API 调用」的门禁，避免浏览器 favicon 之类的
	// 普通请求把事件表灌满。
	if isTrustedHost(host, config) {
		if config.enableAuthzFeature && path != "" && !isAuthenticated() {
			for _, cat := range config.categories {
				if matchedPattern := matchPathPattern(path, cat); matchedPattern != "" {
					reportDetectEvent(config, detectTypeUnauthorized, host, cat.Name, cat.RiskLevel,
						"allowed", "ai_route_unauthenticated pattern="+matchedPattern+" path="+path)
					break
				}
			}
		}
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
				return reportAndBlock(ctx, config, cat, host, feature, matchedPattern, path)
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

	// 事件表的 domain 取请求的 :authority（headers 阶段已剥端口），body 阶段需重新读取
	host := ""
	if h, err := proxywasm.GetHttpRequestHeader(":authority"); err == nil {
		host = strings.ToLower(stripPortFromHost(h))
	}

	// JSON body feature: look up configured fields (gjson path semantics)
	for _, cat := range config.categories {
		if len(cat.BodyFeatures) == 0 {
			continue
		}
		for _, field := range cat.BodyFeatures {
			// gjson field lookup: top-level or nested (e.g. "model", "messages", "input.prompt")
			if gjson.GetBytes(body, field).Exists() {
				return reportAndBlock(ctx, config, cat, host, featureJsonBody, field, string(body))
			}
		}
	}

	return types.ActionContinue
}

// reportAndBlock emits the detection metric + log and blocks in enforcement mode.
// Monitoring mode always continues; the ctx hit marker prevents duplicate body detection.
// host 是请求的 :authority（已剥端口），作为事件表的 domain 写入；domain 是命中的
// 特征值（域名 / 路径模式 / JSON 字段），只用于指标维度与日志。
func reportAndBlock(ctx wrapper.HttpContext, config AiShadowDetectConfig, cat CategoryConfig,
	host, feature, domain, detail string) types.Action {

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

	// sai-b17: 持久化到事件表。页面三处取数（列表/KPI/趋势）读的都是
	// ai_shadow_detect_event，只打指标不会出现在页面上。
	reportDetectEvent(config, detectTypeAccess, host, cat.Name, cat.RiskLevel, status,
		"feature="+feature+" matched="+domain)

	// Block in enforcement mode
	if config.mode == "enforcement" {
		proxywasm.SendHttpResponseWithDetail(config.blockedCode,
			"ai-shadow-detect.blocked", nil, []byte(config.blockedMessage), -1)
		return types.ActionPause
	}

	return types.ActionContinue
}

// isAuthenticated reports whether key-auth (AUTHN stage, runs before this plugin)
// resolved a consumer identity for this request. key-auth only writes the header
// after successful authentication, so an absent/empty header means unauthenticated.
func isAuthenticated() bool {
	consumer, err := proxywasm.GetHttpRequestHeader("x-mse-consumer")
	if err != nil {
		return false
	}
	return strings.TrimSpace(consumer) != ""
}

// reportDetectEvent posts a single detection event to the Console event store
// (POST /v1/ai-shadow/detect-events). Best-effort and asynchronous: a failure only
// logs, it never changes the detection decision on the request path.
// 这里用包级 log（与 reportAndBlock 一致）：该函数没有 log.Log 实例可传。
func reportDetectEvent(config AiShadowDetectConfig, detectType, domain, category,
	risk, status, detail string) {
	if config.reportFQDN == "" || strings.TrimSpace(domain) == "" {
		return
	}
	srcIP, _ := proxywasm.GetHttpRequestHeader("x-forwarded-for")
	if i := strings.Index(srcIP, ","); i != -1 {
		srcIP = srcIP[:i]
	}
	srcIP = strings.TrimSpace(srcIP)
	if srcIP == "" {
		srcIP = "unknown"
	}
	sessionID, _ := proxywasm.GetHttpRequestHeader("x-agent-session-id")
	body, err := json.Marshal(map[string]interface{}{
		"events": []map[string]interface{}{{
			"detectType": detectType,
			"domain":     domain,
			"category":   category,
			"riskLevel":  risk,
			"status":     status,
			"source":     "gateway",
			"srcIp":      srcIP,
			"sessionId":  sessionID,
			"detail":     detail,
			"eventTime":  time.Now().UnixMilli(),
		}},
	})
	if err != nil {
		log.Errorf("ai-shadow-detect: build report body failed: %v", err)
		return
	}
	headers := [][2]string{{"Content-Type", "application/json"}}
	if config.reportToken != "" {
		headers = append(headers, [2]string{"X-Collector-Token", config.reportToken})
	}
	client := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: config.reportFQDN, Port: config.reportPort})
	if dispatchErr := client.Post("/v1/ai-shadow/detect-events", headers, body,
		func(statusCode int, responseHeaders http.Header, responseBody []byte) {
			if statusCode != http.StatusOK {
				log.Errorf("ai-shadow-detect: report rejected status=%d body=%s", statusCode, string(responseBody))
			}
		}, 1500); dispatchErr != nil {
		log.Errorf("ai-shadow-detect: report dispatch error: %v", dispatchErr)
	}
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
