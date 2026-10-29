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

// 判定面（L3 归属口径）：通道内的问题进 route，绕道的进 shadow。
const (
	surfaceRoute  = "route"
	surfaceShadow = "shadow"
)

// verdict 取值。non_shadow 不产生事件（A2 短路直接放行），
// 字段仍随事件下发，供事件表结构与后续聚合口径统一。
const verdictShadow = "shadow"

// reason 承载 shadow 的细分原因
const (
	reasonOffChannel         = "off_channel"          // 不在已登记通道
	reasonNoConsumer         = "no_consumer"          // 通道内，但未认证
	reasonConsumerNotAllowed = "consumer_not_allowed" // 通道内，已认证但未被授权调用该通道
)

// 默认上报目标：集群内 Console（与 key-auth 的 sai-b15 保持一致）
const (
	defaultReportFQDN = "higress-console.higress-system.svc.cluster.local"
	defaultReportPort = 8080
)

// A1：S1 判定所用请求头的默认名。可配置是为了避免硬编码，
// 默认值必须与 AI Route 的 header 匹配注解、key-auth 的写入头保持一致。
const (
	defaultRouteHeader    = "x-higress-llm-model"
	defaultConsumerHeader = "x-asg-consumer-ok"
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
	counterMetrics    map[string]proxywasm.MetricCounter

	// A1（2026-10-29）：S1 已登记通道白名单。三个集合全部由 Console 派生下发
	// （AiChannelDerivationService），不接受手工维护。全部留空时短路不会触发，
	// 行为与改造前完全一致。
	aiRouteModels        []string // S1a：AI Route 的 model 头前缀集合（predicate=PRE）
	aiRouteModelExacts   []string // S1a：AI Route 的 model 头精确集合（predicate=EQUAL）
	authorizedProxyHosts []string // S1b：已登记代理域名（授权域名 ∩ ingress host）
	routeHeader          string   // 取 model 的请求头，默认 x-higress-llm-model
	consumerHeader       string   // key-auth 的授权标记头，默认 x-asg-consumer-ok

	// sai-b17: detect-events 上报。页面（「检测到的AI服务访问」/KPI/趋势）读的是
	// ai_shadow_detect_event 表，只打 Prometheus 指标不会出现在页面上，故必须逐条上报。
	reportFQDN  string
	reportPort  int64
	reportToken string
}

// hitResult records a detection hit with its feature type
type hitResult struct {
	category CategoryConfig
	feature  string // one of featureDomain/featurePath/featureJsonBody/featureDomainSSE/featurePathSSE
	domain   string // matched domain (may be empty for path/body hits)
	detail   string // matched value for logging (path or body field)
}

// detectEvent 是一条上报事件。用结构体而不是位置参数：
// 字段已有 11 个，位置参数极易传错顺序，且后续还会加。
type detectEvent struct {
	detectType string
	host       string // 请求的 :authority（已剥端口）
	category   string
	risk       string
	status     string
	detail     string
	surface    string // route | shadow
	verdict    string // shadow（non_shadow 不上报）
	reason     string // off_channel | no_consumer | consumer_not_allowed
	routeHint  string // 命中的通道依据，如 model=mock-llm / host=www.deepseek.com
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

	// A1：S1 白名单。空值必须过滤掉——空前缀会前缀匹配所有 model，等于全域放行。
	for _, m := range json.Get("ai_route_models").Array() {
		if v := strings.TrimSpace(m.String()); v != "" {
			config.aiRouteModels = append(config.aiRouteModels, v)
		}
	}
	for _, m := range json.Get("ai_route_model_exacts").Array() {
		if v := strings.TrimSpace(m.String()); v != "" {
			config.aiRouteModelExacts = append(config.aiRouteModelExacts, v)
		}
	}
	for _, h := range json.Get("authorized_proxy_hosts").Array() {
		if v := strings.ToLower(strings.TrimSpace(h.String())); v != "" {
			config.authorizedProxyHosts = append(config.authorizedProxyHosts, v)
		}
	}
	config.routeHeader = strings.TrimSpace(json.Get("route_header").String())
	if config.routeHeader == "" {
		config.routeHeader = defaultRouteHeader
	}
	config.consumerHeader = strings.TrimSpace(json.Get("consumer_header").String())
	if config.consumerHeader == "" {
		config.consumerHeader = defaultConsumerHeader
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

// onHttpRequestHeaders 是 wrapper 的唯一入口：先判定，再把内部头清掉。
// A4：x-asg-consumer-ok 只供本插件判定，绝不能带到上游（哪怕上游是自有 LLM 网关）。
func onHttpRequestHeaders(ctx wrapper.HttpContext, config AiShadowDetectConfig, log log.Log) types.Action {
	action := decideRequestHeaders(ctx, config, log)
	removeInternalHeaders(config)
	return action
}

func decideRequestHeaders(ctx wrapper.HttpContext, config AiShadowDetectConfig, log log.Log) types.Action {
	if len(config.categories) == 0 {
		// 认证维度同样依赖 categories 做 path 门禁，没有分类就无从判定
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

	// A2（2026-10-29）：S1 —— 请求是否落在已登记 AI 通道上。判定式见方案 2.1：
	//   non_shadow ⟺ S1 ∧ S2  → 合规调用，直接放行且不产生任何事件
	//   S1 ∧ ¬S2   → 通道内未授权，上报 shadow（surface=route），不阻断
	// 只有 S1 ∧ S2 才提前放行。S1 ∧ ¬S2 必须继续走域名判定：model-router 会
	// 用请求体的 model 补写 x-higress-llm-model，若在这里一并放行，
	// 「绕道公网 AI + body 里写一个内部模型名」就会在 enforcement 下被放过。
	s1, channelHint := matchedRegisteredChannel(config, host)
	if s1 && isAuthorizedConsumer(config) {
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

	// S1 ∧ ¬S2 且域名未命中任何分类：确实是自有通道上的调用，只是没被授权。
	// 归到 route 面，不做路径/载荷特征判定——那会把自有通道的正常调用重复计成影子。
	if s1 {
		reportChannelUnauthorized(config, path, host, channelHint)
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
	// 走到这里的请求都没落在已登记通道上，故 surface=shadow、reason=off_channel。
	reportDetectEvent(config, detectEvent{
		detectType: detectTypeAccess,
		host:       host,
		category:   cat.Name,
		risk:       cat.RiskLevel,
		status:     status,
		detail:     "feature=" + feature + " matched=" + domain,
		surface:    surfaceShadow,
		verdict:    verdictShadow,
		reason:     reasonOffChannel,
	})

	// Block in enforcement mode
	if config.mode == "enforcement" {
		proxywasm.SendHttpResponseWithDetail(config.blockedCode,
			"ai-shadow-detect.blocked", nil, []byte(config.blockedMessage), -1)
		return types.ActionPause
	}

	return types.ActionContinue
}

// matchedRegisteredChannel 判断 S1：S1a 命中已登记 AI Route 的 model 头，或 S1b 命中已登记代理域名。
// 返回命中依据（写入事件的 routeHint，便于定位是哪条通道）。
// 白名单为空时两个循环都不进入，等价于「不识别任何通道」，即改造前行为。
func matchedRegisteredChannel(config AiShadowDetectConfig, host string) (bool, string) {
	if config.routeHeader != "" {
		if v, err := proxywasm.GetHttpRequestHeader(config.routeHeader); err == nil {
			model := strings.TrimSpace(v)
			if model != "" {
				for _, m := range config.aiRouteModelExacts {
					if model == m {
						return true, "model=" + model
					}
				}
				for _, m := range config.aiRouteModels {
					if strings.HasPrefix(model, m) {
						return true, "model=" + model
					}
				}
			}
		}
	}
	if host != "" {
		for _, h := range config.authorizedProxyHosts {
			if host == h {
				return true, "host=" + host
			}
		}
	}
	return false, ""
}

// isAuthorizedConsumer 判断 S2：既已认证（x-mse-consumer），又通过 allow 校验
// （x-asg-consumer-ok=true，仅在 key-auth 的 allow 命中分支写入）。
// 只有 S2a 不够：identify_only 模式下「认证了但不在 allow」也会被放行。
func isAuthorizedConsumer(config AiShadowDetectConfig) bool {
	consumer, err := proxywasm.GetHttpRequestHeader("x-mse-consumer")
	if err != nil || strings.TrimSpace(consumer) == "" {
		return false
	}
	ok, err := proxywasm.GetHttpRequestHeader(config.consumerHeader)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(ok), "true")
}

// reportChannelUnauthorized 上报「已登记通道上的未授权调用」。
// 用 KB 的 path 特征做门禁，避免 favicon 之类普通请求把事件表灌满（与 sai-b18 一致）。
// 只上报、不阻断：认证拒绝由 key-auth（AUTHN 阶段）负责，插件处在 AUTHZ 阶段
// 只能看到已被放行的请求，重复阻断会掩盖真实原因。
func reportChannelUnauthorized(config AiShadowDetectConfig, path, host, channelHint string) {
	if path == "" {
		return
	}
	// 到这里 S2 一定不成立：要么没有身份，要么有身份但没通过 allow。
	reason := reasonNoConsumer
	if consumer, err := proxywasm.GetHttpRequestHeader("x-mse-consumer"); err == nil &&
		strings.TrimSpace(consumer) != "" {
		reason = reasonConsumerNotAllowed
	}
	for _, cat := range config.categories {
		matchedPattern := matchPathPattern(path, cat)
		if matchedPattern == "" {
			continue
		}
		reportDetectEvent(config, detectEvent{
			detectType: detectTypeUnauthorized,
			host:       host,
			category:   cat.Name,
			risk:       cat.RiskLevel,
			status:     "allowed",
			detail:     "reason=" + reason + " " + channelHint + " pattern=" + matchedPattern + " path=" + path,
			surface:    surfaceRoute,
			verdict:    verdictShadow,
			reason:     reason,
			routeHint:  channelHint,
		})
		return
	}
}

// removeInternalHeaders 删除只供网关内部判定用的请求头，避免泄漏到上游。
func removeInternalHeaders(config AiShadowDetectConfig) {
	if config.consumerHeader == "" {
		return
	}
	// 未认证请求本来就没有该头，删除失败属正常情况
	_ = proxywasm.RemoveHttpRequestHeader(config.consumerHeader)
}

// reportDetectEvent posts a single detection event to the Console event store
// (POST /v1/ai-shadow/detect-events). Best-effort and asynchronous: a failure only
// logs, it never changes the detection decision on the request path.
// 这里用包级 log（与 reportAndBlock 一致）：该函数没有 log.Log 实例可传。
func reportDetectEvent(config AiShadowDetectConfig, ev detectEvent) {
	if config.reportFQDN == "" {
		return
	}
	// A4：Host 为空时必须落 unknown。原逻辑在这里直接 return，
	// 相当于「没有 Host 的命中全部静默丢弃」，是一处静默漏检。
	host := strings.TrimSpace(ev.host)
	if host == "" {
		host = "unknown"
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
			"detectType": ev.detectType,
			"domain":     host,
			"category":   ev.category,
			"riskLevel":  ev.risk,
			"status":     ev.status,
			"source":     "gateway",
			"srcIp":      srcIP,
			"sessionId":  sessionID,
			"detail":     ev.detail,
			"surface":    ev.surface,
			"verdict":    ev.verdict,
			"reason":     ev.reason,
			"routeHint":  ev.routeHint,
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
