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
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	pluginName = "ai-prompt-guard"
	// prompt_guard_event 写入 wasm.ai_log 一级 filter state（per-request 共享），
	// 供 ai-agent-guard 读取；两级路径 security_events 跨 VM 不可见。
	PromptGuardEventKey = "prompt_guard_event"

	// 写入 ai_log 的事件体必须有上界：access log 模板会把整个 wasm.ai_log
	// 过滤状态打进单行 JSON，超长行会被采集器静默丢弃。
	maxHitContentRunes  = 512
	maxMatchedTextRunes = 128
	maxReasonRunes      = 512
	maxEmittedEvents    = 20
	maxAIlogEventBytes  = 8192
)

func main() {}

func init() {
	wrapper.SetCtx(
		pluginName,
		wrapper.ParseConfig(parseConfig),
		wrapper.ProcessRequestHeaders(onHttpRequestHeaders),
		wrapper.ProcessRequestBody(onHttpRequestBody),
		wrapper.ProcessResponseHeaders(onHttpResponseHeaders),
		wrapper.ProcessResponseBody(onHttpResponseBody),
	)
}

// RuleItem is a named detection rule written by the console page schema
// (denyRules/allowRules), kept compatible with legacy deny_patterns/allow_patterns.
type RuleItem struct {
	Name      string `json:"name"`
	Regex     string `json:"regex"`
	MatchType string `json:"matchType"` // "regex" (default) or "contains"
}

// KeywordRuleGroup is a content-compliance rule group aligned with
// GB/T 45654-2025 Appendix A risk categories (name carries the standard code).
type KeywordRuleGroup struct {
	Name     string   `json:"name"`
	Keywords []string `json:"keywords"`
	Patterns []string `json:"patterns"`
	Enabled  *bool    `json:"enabled"` // nil defaults to true
}

// AdvisoryRule carries a non-blocking safety note injected into responses
// when a high-stakes service scenario is hit (GB/T 45654 Appendix A.5).
type AdvisoryRule struct {
	Name     string   `json:"name"`
	Keywords []string `json:"keywords"`
	Advice   string   `json:"advice"`
	Enabled  *bool    `json:"enabled"`
}

// PromptGuardConfig contains configuration for malicious prompt detection
type PromptGuardConfig struct {
	// DenyPatterns contains regex patterns to block malicious prompts (legacy schema)
	DenyPatterns []string `json:"deny_patterns"`
	// AllowPatterns contains regex patterns to explicitly allow (bypass deny) (legacy schema)
	AllowPatterns []string `json:"allow_patterns"`
	// DenyRules / AllowRules are the console page schema rules (v1.0.4+)
	DenyRules  []RuleItem `json:"denyRules"`
	AllowRules []RuleItem `json:"allowRules"`
	// KeywordRules are grouped content-compliance keyword libraries (GB/T 45654 App. A)
	KeywordRules []KeywordRuleGroup `json:"keywordRules"`
	// AdvisoryRules append a safety note to responses instead of blocking (A.5)
	AdvisoryRules []AdvisoryRule `json:"advisoryRules"`
	// DetectMode: "deny" (default) blocks on hit; "monitor" only logs an event and passes.
	// parseConfig normalizes block/deny->deny and detect/monitor/observe/pass/dry_run->monitor,
	// and honors a `mode` alias key, so the on-hit action stays a single unambiguous concept.
	DetectMode string `json:"detectMode"`
	// RejectMessage is the page-schema alias of deny_message
	RejectMessage string `json:"rejectMessage"`
	// CheckRequest enables input-side detection (default true)
	CheckRequest bool `json:"checkRequest"`
	// CheckResponse enables output-side detection (default false)
	CheckResponse bool `json:"checkResponse"`
	// DenyCode is the HTTP status code to return when blocked
	DenyCode int `json:"deny_code"`
	// DenyMessage is the message to return when blocked
	DenyMessage string `json:"deny_message"`
	// CaseSensitive indicates whether pattern matching is case-sensitive
	CaseSensitive bool `json:"case_sensitive"`
	// EnableNormalization enables decoding (rot13/base64/unicode/url/hex) before deny matching
	EnableNormalization bool `json:"enable_normalization"`
	// MaxDecodeCandidates limits the number of decode candidates
	MaxDecodeCandidates int `json:"max_decode_candidates"`

	// Compiled patterns (internal use)
	compiledDenyPatterns  []*compiledRule
	compiledAllowPatterns []*compiledRule
	compiledKeywordGroups []compiledKeywordGroup
	compiledAdvisory      []compiledAdvisory
}

// compiledRule pairs a regex with its optional rule name for event detail.
type compiledRule struct {
	name string
	re   *regexp.Regexp
}

// compiledKeywordGroup holds lower-cased keywords plus compiled variants for one risk group.
type compiledKeywordGroup struct {
	name     string
	keywords []string
	patterns []*regexp.Regexp
}

type compiledAdvisory struct {
	name     string
	keywords []string
	advice   string
}

func compileRuleItem(item RuleItem, caseSensitive bool) (*compiledRule, error) {
	pattern := item.Regex
	if item.MatchType == "contains" {
		pattern = regexp.QuoteMeta(item.Regex)
	}
	if !caseSensitive && !strings.HasPrefix(pattern, "(?i)") {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &compiledRule{name: item.Name, re: re}, nil
}

func parseConfig(json gjson.Result, config *PromptGuardConfig) error {
	// Set defaults
	config.DenyCode = 403
	config.DenyMessage = "Request blocked by prompt guard"
	config.CaseSensitive = false
	config.EnableNormalization = true
	config.MaxDecodeCandidates = defaultMaxCandidates
	config.CheckRequest = true
	config.DetectMode = "deny"

	if json.Get("enable_normalization").Exists() {
		config.EnableNormalization = json.Get("enable_normalization").Bool()
	}
	if json.Get("max_decode_candidates").Exists() {
		config.MaxDecodeCandidates = int(json.Get("max_decode_candidates").Int())
	}
	if json.Get("deny_code").Exists() {
		config.DenyCode = int(json.Get("deny_code").Int())
	}
	if json.Get("deny_message").Exists() {
		config.DenyMessage = json.Get("deny_message").String()
	}
	if json.Get("rejectMessage").Exists() {
		config.RejectMessage = json.Get("rejectMessage").String()
	}
	if config.RejectMessage != "" {
		config.DenyMessage = config.RejectMessage
	}
	if json.Get("case_sensitive").Exists() {
		config.CaseSensitive = json.Get("case_sensitive").Bool()
	}
	// detectMode canonical values: "deny" = block on hit, "monitor" = record event and pass.
	// Normalize naming aliases and accept the `mode` alias key so the single on-hit-action
	// concept stays unambiguous no matter which spelling the console page writes:
	//   block/deny -> deny ; detect/monitor/observe/pass/dry_run -> monitor
	rawMode := ""
	if json.Get("detectMode").Exists() {
		rawMode = json.Get("detectMode").String()
	} else if json.Get("mode").Exists() {
		rawMode = json.Get("mode").String()
	}
	if rawMode != "" {
		switch strings.ToLower(rawMode) {
		case "deny", "block":
			config.DetectMode = "deny"
		case "monitor", "detect", "observe", "pass", "dry_run", "dryrun":
			config.DetectMode = "monitor"
		default:
			log.Warnf("unknown detectMode %q, fallback to deny", rawMode)
			config.DetectMode = "deny"
		}
	}
	if json.Get("checkRequest").Exists() {
		config.CheckRequest = json.Get("checkRequest").Bool()
	}
	if json.Get("checkResponse").Exists() {
		config.CheckResponse = json.Get("checkResponse").Bool()
	}

	// Parse legacy deny_patterns
	denyPatterns := json.Get("deny_patterns").Array()
	config.DenyPatterns = make([]string, 0, len(denyPatterns))
	for _, pattern := range denyPatterns {
		patternStr := pattern.String()
		config.DenyPatterns = append(config.DenyPatterns, patternStr)
		rule, err := compileRuleItem(RuleItem{Regex: patternStr, MatchType: "regex"}, config.CaseSensitive)
		if err != nil {
			log.Warnf("Invalid deny pattern '%s': %v", patternStr, err)
			continue
		}
		config.compiledDenyPatterns = append(config.compiledDenyPatterns, rule)
	}

	// Parse page-schema denyRules
	for _, raw := range json.Get("denyRules").Array() {
		item := RuleItem{Name: raw.Get("name").String(), Regex: raw.Get("regex").String(), MatchType: raw.Get("matchType").String()}
		if item.Regex == "" {
			continue
		}
		rule, err := compileRuleItem(item, config.CaseSensitive)
		if err != nil {
			log.Warnf("Invalid denyRule '%s': %v", item.Name, err)
			continue
		}
		config.compiledDenyPatterns = append(config.compiledDenyPatterns, rule)
	}

	// Parse legacy allow_patterns
	allowPatterns := json.Get("allow_patterns").Array()
	config.AllowPatterns = make([]string, 0, len(allowPatterns))
	for _, pattern := range allowPatterns {
		patternStr := pattern.String()
		config.AllowPatterns = append(config.AllowPatterns, patternStr)
		rule, err := compileRuleItem(RuleItem{Regex: patternStr, MatchType: "regex"}, config.CaseSensitive)
		if err != nil {
			log.Warnf("Invalid allow pattern '%s': %v", patternStr, err)
			continue
		}
		config.compiledAllowPatterns = append(config.compiledAllowPatterns, rule)
	}

	// Parse page-schema allowRules
	for _, raw := range json.Get("allowRules").Array() {
		item := RuleItem{Name: raw.Get("name").String(), Regex: raw.Get("regex").String(), MatchType: raw.Get("matchType").String()}
		if item.Regex == "" {
			continue
		}
		rule, err := compileRuleItem(item, config.CaseSensitive)
		if err != nil {
			log.Warnf("Invalid allowRule '%s': %v", item.Name, err)
			continue
		}
		config.compiledAllowPatterns = append(config.compiledAllowPatterns, rule)
	}

	// Parse keywordRules groups
	for _, raw := range json.Get("keywordRules").Array() {
		group := KeywordRuleGroup{Name: raw.Get("name").String()}
		if raw.Get("enabled").Exists() {
			enabled := raw.Get("enabled").Bool()
			group.Enabled = &enabled
		}
		if group.Enabled != nil && !*group.Enabled {
			continue
		}
		for _, kw := range raw.Get("keywords").Array() {
			k := strings.ToLower(kw.String())
			if k != "" {
				group.Keywords = append(group.Keywords, k)
			}
		}
		cg := compiledKeywordGroup{name: group.Name, keywords: group.Keywords}
		for _, p := range raw.Get("patterns").Array() {
			pattern := p.String()
			if pattern == "" {
				continue
			}
			if !config.CaseSensitive && !strings.HasPrefix(pattern, "(?i)") {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Warnf("Invalid keyword rule pattern in '%s': %v", group.Name, err)
				continue
			}
			cg.patterns = append(cg.patterns, re)
		}
		if len(cg.keywords) == 0 && len(cg.patterns) == 0 {
			continue
		}
		config.compiledKeywordGroups = append(config.compiledKeywordGroups, cg)
	}

	// Parse advisoryRules
	for _, raw := range json.Get("advisoryRules").Array() {
		if raw.Get("enabled").Exists() && !raw.Get("enabled").Bool() {
			continue
		}
		adv := compiledAdvisory{name: raw.Get("name").String(), advice: raw.Get("advice").String()}
		for _, kw := range raw.Get("keywords").Array() {
			k := strings.ToLower(kw.String())
			if k != "" {
				adv.keywords = append(adv.keywords, k)
			}
		}
		if len(adv.keywords) == 0 || adv.advice == "" {
			continue
		}
		config.compiledAdvisory = append(config.compiledAdvisory, adv)
	}

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config PromptGuardConfig) types.Action {
	ctx.DisableReroute()
	proxywasm.RemoveHttpRequestHeader("content-length")
	return types.ActionContinue
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, config PromptGuardConfig) types.Action {
	if !config.CheckResponse {
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}
	ct, _ := proxywasm.GetHttpResponseHeader("content-type")
	if strings.Contains(ct, "text/event-stream") {
		// Streaming (SSE) responses are not buffered; known limitation.
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}
	// Response body may be rewritten by advisory injection, changing its length.
	// Drop the upstream content-length here (headers not sent yet) so Envoy
	// recomputes it; removing it in onHttpResponseBody is too late.
	proxywasm.RemoveHttpResponseHeader("content-length")
	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config PromptGuardConfig, body []byte) types.Action {
	if !config.CheckRequest {
		return types.ActionContinue
	}
	// Extract messages from request body
	messages := gjson.GetBytes(body, "messages")
	if !messages.Exists() {
		log.Debugf("No messages field found in request body")
		return types.ActionContinue
	}

	for _, msg := range messages.Array() {
		content := msg.Get("content").String()
		if content == "" {
			continue
		}
		hit, info := detectContent(content, config)
		info.content = content
		if hit {
			if info.kind == "prompt_injection" {
				info.confidence, info.evidence = assessInjection(content, info.matchedText, msg.Get("role").String())
			}
			if config.DetectMode == "monitor" {
				log.Infof("Malicious prompt detected (group=%s method=%s) in monitor mode, request passed", info.group, info.method)
				emitSecurityEvent(ctx, eventFor(info, "request", config.DetectMode))
				continue
			}
			if info.confidence == confidenceLow {
				log.Infof("Injection rule hit downgraded to alert (group=%s evidence=%s), request passed", info.group, info.evidence)
				emitSecurityEvent(ctx, eventFor(info, "request", config.DetectMode))
				continue
			}
			log.Infof("Malicious prompt detected (group=%s method=%s), blocking request", info.group, info.method)
			emitSecurityEvent(ctx, eventFor(info, "request", config.DetectMode))
			sendDenyResponse(config.DenyCode, config.DenyMessage)
			return types.ActionContinue
		}
	}

	return types.ActionContinue
}

type hitInfo struct {
	group       string
	detail      string
	method      string // "plain", decode method, or "keyword"
	kind        string // "prompt_injection" or "content_violation"
	content     string // 被检测的原文（由回调填入）
	matchedText string // 实际命中的关键词 / 正则片段
	ruleGroup   string // denyRules / keywordRules / normalized_deny
	confidence  string // prompt_injection 命中经上下文复判后的置信度："" / high / low
	evidence    string // 复判依据，写进事件 reason 供审计详情阅读
}

// detectContent checks text against allow (bypass), deny patterns/rules,
// keyword groups and advisory groups. Advisory hits are not blocking here.
func detectContent(text string, config PromptGuardConfig) (bool, hitInfo) {
	if matchesAnyCompiledRule(text, config.compiledAllowPatterns) {
		log.Debugf("Content matches allow rule, bypassing deny check")
		return false, hitInfo{}
	}
	// deny rules: plain regex first, then decoded variants
	for _, rule := range config.compiledDenyPatterns {
		if rule.re.MatchString(text) {
			name := rule.name
			if name == "" {
				name = "deny_pattern"
			}
			return true, hitInfo{group: name, detail: "Detected prompt injection / jailbreak pattern: " + name, method: "plain", kind: "prompt_injection", matchedText: rule.re.FindString(text), ruleGroup: "denyRules"}
		}
	}
	if config.EnableNormalization {
		for _, c := range NormalizeForDetection(text, config.MaxDecodeCandidates) {
			if c.Method == "original" {
				continue
			}
			for _, rule := range config.compiledDenyPatterns {
				if rule.re.MatchString(c.Text) {
					name := rule.name
					if name == "" {
						name = "deny_pattern"
					}
					return true, hitInfo{group: name, detail: "Detected prompt injection / jailbreak pattern: " + name + " (decoded via " + c.Method + ")", method: c.Method, kind: "prompt_injection", matchedText: rule.re.FindString(c.Text), ruleGroup: "normalized_deny"}
				}
			}
		}
	}
	// keyword groups (GB/T 45654 Appendix A risk library)
	lower := strings.ToLower(text)
	for _, g := range config.compiledKeywordGroups {
		for _, kw := range g.keywords {
			if strings.Contains(lower, kw) {
				return true, hitInfo{group: g.name, detail: "GB/T 45654 Appendix A risk hit [" + g.name + "] keyword: " + kw, method: "keyword", kind: "content_violation", matchedText: kw, ruleGroup: "keywordRules"}
			}
		}
		for _, re := range g.patterns {
			if re.MatchString(text) {
				return true, hitInfo{group: g.name, detail: "GB/T 45654 Appendix A risk hit [" + g.name + "] variant pattern", method: "regex", kind: "content_violation", matchedText: re.FindString(text), ruleGroup: "keywordRules"}
			}
		}
	}
	return false, hitInfo{}
}

// 注入类规则命中只作为「候选证据」：规则本身无法区分「攻击指令」与
// 「安全规范/技术文档里对注入术语的引用、元讨论」。下面三组词表用于在命中点
// 附近做一次廉价复判，窗口有界，避免数百 KB 上下文带来额外开销。
// 注意：这是降低误报的启发式，不是安全边界；deny 模式仍需配合其它防线。
const (
	injectionContextRunes = 96
	confidenceHigh        = "high"
	confidenceLow         = "low"
)

var (
	// 指令性动词：与 injectionTargetWords 共现才构成强意图。
	injectionIntentWords = []string{
		"ignore", "forget", "disregard", "override", "bypass", "reveal",
		"print", "dump", "leak", "disclose", "output", "repeat",
		"忽略", "忘记", "无视", "绕过", "覆写", "泄露", "输出", "打印", "重复",
	}
	injectionTargetWords = []string{
		"instructions", "instruction", "prompt", "rules", "system", "previous", "above",
		"指令", "提示词", "规则", "系统", "上文",
	}
	// 只保留显式的文档/教学/元讨论标记：通用否定词（不要/禁止）与弱连接词
	// （例如/比如/如下）会被攻击者直接拼在载荷前，放进这里等于提供一行绕过。
	injectionMetaWords = []string{
		"示例", "术语", "称为", "定义", "解释", "文档", "规范", "说明", "引用",
		"上下文数据", "框架文本", "带偏", "误报", "命中", "规则名", "教学",
		"不是语言示范", "这类", "检测方法", "什么是", "是什么", "什么意思",
		"for example", "such as", "e.g.", "refers to", "is called", "definition",
		"what is", "what are", "meaning of",
	}
	// 疑问词 + 否定结构 + 被动语态共现 => 元讨论（如 explain why ... should not be revealed）。
	// 要求被动短语前后两侧都不出现「指令动词+目标词」组合，避免拼接真攻击绕过。
	injectionInterrogativeWords = []string{"explain", "why"}
	injectionNegationWords      = []string{"should not", "shouldn't"}
	injectionPassiveWords       = []string{
		"be revealed", "be disclosed", "be leaked", "be exposed", "be output", "be printed", "be shown",
	}
)

func containsAnyWord(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// contextWindow 以命中位置为中心取有限窗口（按 rune，中文不会被截半）。
// 只把命中点附近的字节片段转成 []rune，避免数百 KB 上下文被整体转换。
func contextWindow(content, matched string, width int) string {
	idx := 0
	if matched != "" {
		if i := strings.Index(content, matched); i >= 0 {
			idx = i
		}
	}
	byteWidth := width * 4 // UTF-8 单字符最多 4 字节，足够覆盖 width 个 rune
	start := idx - byteWidth
	if start < 0 {
		start = 0
	}
	for start > 0 && content[start]&0xC0 == 0x80 {
		start--
	}
	end := idx + byteWidth
	if end > len(content) {
		end = len(content)
	}
	r := []rune(content[start:end])
	center := len([]rune(content[start:idx]))
	lo := center - width
	if lo < 0 {
		lo = 0
	}
	hi := center + width
	if hi > len(r) {
		hi = len(r)
	}
	return string(r[lo:hi])
}

// assessInjection 把注入类规则命中转成置信度。low 只记录告警、不拦截。
// 所有 role 照常检测以保留可见性；system/developer/assistant 按应用侧文本对待，
// 只有出现指令性动词与目标词时才升为 high，避免「载荷塞进 system」被静默放过。
func assessInjection(content, matched, role string) (string, string) {
	lower := strings.ToLower(contextWindow(content, matched, injectionContextRunes))
	intent := containsAnyWord(lower, injectionIntentWords) && containsAnyWord(lower, injectionTargetWords)
	meta := containsAnyWord(lower, injectionMetaWords)
	if !meta && containsAnyWord(lower, injectionInterrogativeWords) && containsAnyWord(lower, injectionNegationWords) {
		// 以被动短语为界，前后两侧都不得出现「指令动词+目标词」：
		// 否则像 "ignore previous instructions, explain why it should not be revealed" 这类
		// 把攻击拼在元讨论句前的写法会被误降级。
		passiveStart, passiveEnd := -1, -1
		for _, w := range injectionPassiveWords {
			if i := strings.Index(lower, w); i >= 0 {
				if passiveStart < 0 || i < passiveStart {
					passiveStart = i
				}
				if passiveEnd < i+len(w) {
					passiveEnd = i + len(w)
				}
			}
		}
		if passiveEnd > 0 {
			before, after := lower[:passiveStart], lower[passiveEnd:]
			attackBefore := containsAnyWord(before, injectionIntentWords) && containsAnyWord(before, injectionTargetWords)
			attackAfter := containsAnyWord(after, injectionIntentWords) && containsAnyWord(after, injectionTargetWords)
			if !attackBefore && !attackAfter {
				meta = true
			}
		}
	}
	trusted := role == "system" || role == "developer" || role == "assistant"
	switch {
	case meta:
		return confidenceLow, "命中处为引用/元讨论语境"
	case trusted && !intent:
		return confidenceLow, "应用侧文本且无指令性动词"
	case intent:
		return confidenceHigh, "命中处含指令性动词与目标词"
	default:
		return confidenceHigh, "命中处无引用语境"
	}
}

// boundedText 按 rune 截断，避免把中文截成半个字。
func boundedText(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "…"
}

// boundedExcerpt 以命中位置为中心截取原文：既保留「具体是哪段内容触发」，
// 又不会把数百 KB 的完整上下文写进 ai_log / access log。
func boundedExcerpt(content, matched string, maxRunes int) string {
	r := []rune(content)
	if len(r) <= maxRunes {
		return content
	}
	start := 0
	if matched != "" {
		if idx := strings.Index(content, matched); idx >= 0 {
			start = len([]rune(content[:idx])) - maxRunes/2
			if start < 0 {
				start = 0
			}
		}
	}
	if start+maxRunes > len(r) {
		start = len(r) - maxRunes
	}
	prefix, suffix := "", ""
	if start > 0 {
		prefix = "…"
	}
	if start+maxRunes < len(r) {
		suffix = "…"
	}
	return prefix + string(r[start:start+maxRunes]) + suffix
}

func eventFor(info hitInfo, direction string, mode string) SecurityEvent {
	severity := "high"
	score := 80
	if info.kind == "content_violation" {
		severity = "high"
		score = 90
	}
	downgraded := info.kind == "prompt_injection" && info.confidence == confidenceLow
	if downgraded {
		severity = "low"
		score = 30
	}
	blocked := mode == "deny" && !downgraded
	matchedText := boundedText(info.matchedText, maxMatchedTextRunes)
	reason := "命中规则[" + info.group + "]，匹配方式=" + info.method
	if matchedText != "" {
		reason += "，命中片段=" + matchedText
	}
	if blocked {
		reason += "；拦截模式已拦截请求"
	} else if downgraded {
		reason += "；上下文复判=" + info.evidence + "，置信度不足，仅记录并放行"
	} else {
		reason += "；检测模式仅告警并放行"
	}
	reason = boundedText(reason, maxReasonRunes)
	return SecurityEvent{
		Type:        info.kind,
		Severity:    severity,
		Source:      pluginName,
		Score:       score,
		Detail:      info.detail,
		Direction:   direction,
		HitContent:  boundedExcerpt(info.content, info.matchedText, maxHitContentRunes),
		RuleName:    info.group,
		RuleGroup:   info.ruleGroup,
		MatchMethod: info.method,
		MatchedText: matchedText,
		Reason:      reason,
		DetectMode:  mode,
		Blocked:     blocked,
		TimestampMs: time.Now().UnixMilli(),
	}
}

func onHttpResponseBody(ctx wrapper.HttpContext, config PromptGuardConfig, body []byte) types.Action {
	if !config.CheckResponse {
		return types.ActionContinue
	}
	text := extractResponseText(body)
	if strings.HasPrefix(strings.TrimSpace(string(body)), "data:") {
		// SSE frames slipping past header check: pass through unbuffered decision
		log.Debugf("SSE response body detected, skipping output-side check")
		return types.ActionContinue
	}
	if text == "" {
		return types.ActionContinue
	}

	hit, info := detectContent(text, config)
	info.content = text
	if hit {
		if info.kind == "prompt_injection" {
			info.confidence, info.evidence = assessInjection(text, info.matchedText, "assistant")
		}
		if config.DetectMode == "monitor" || info.confidence == confidenceLow {
			log.Infof("Violation detected in model output (group=%s confidence=%s), response passed", info.group, info.confidence)
			emitSecurityEvent(ctx, eventFor(info, "response", config.DetectMode))
			return types.ActionContinue
		}
		log.Infof("Violation detected in model output (group=%s method=%s), blocking response", info.group, info.method)
		emitSecurityEvent(ctx, eventFor(info, "response", config.DetectMode))
		sendDenyResponse(config.DenyCode, config.DenyMessage)
		return types.ActionContinue
	}

	// Advisory injection (A.5): append safety note without blocking
	for _, adv := range config.compiledAdvisory {
		lower := strings.ToLower(text)
		for _, kw := range adv.keywords {
			if strings.Contains(lower, kw) {
				advised := appendAdvice(body, adv.advice)
				if advised == nil {
					log.Warnf("advisory rule [%s] injection skipped: unexpected response body structure", adv.name)
					return types.ActionContinue
				}
				log.Infof("Advisory rule [%s] applied to response", adv.name)
				if err := proxywasm.ReplaceHttpResponseBody(advised); err != nil {
					log.Warnf("replace response body failed: %v", err)
				}
				return types.ActionContinue
			}
		}
	}
	return types.ActionContinue
}

// extractResponseText pulls assistant text out of an OpenAI-style completion
// response (or the raw text for non-JSON bodies).
func extractResponseText(body []byte) string {
	if !gjson.ValidBytes(body) {
		return string(body)
	}
	var sb strings.Builder
	choices := gjson.GetBytes(body, "choices")
	if choices.Exists() {
		for _, c := range choices.Array() {
			sb.WriteString(c.Get("message.content").String())
		}
	}
	if sb.Len() == 0 {
		sb.WriteString(gjson.GetBytes(body, "text").String())
	}
	return sb.String()
}

// appendAdvice rebuilds the response body with a safety note appended to the
// first choice message content. Returns nil when the structure is not recognized.
// It uses sjson (structural Set) rather than byte-level string splicing, so it
// works for both literal UTF-8 and \uXXXX-escaped response bodies regardless of
// how the upstream serialized the JSON.
func appendAdvice(body []byte, advice string) []byte {
	path := "choices.0.message.content"
	content := gjson.GetBytes(body, path)
	if !content.Exists() {
		return nil
	}
	note := "\n\n【安全提示】" + advice
	out, err := sjson.SetBytes(body, path, content.String()+note)
	if err != nil || !gjson.ValidBytes(out) {
		return nil
	}
	return out
}

// matchesAnyCompiledRule checks if text matches any of the compiled rules
func matchesAnyCompiledRule(text string, rules []*compiledRule) bool {
	for _, rule := range rules {
		if rule.re.MatchString(text) {
			return true
		}
	}
	return false
}

// matchesAnyPattern checks if text matches any of the compiled patterns (kept for tests)
func matchesAnyPattern(text string, patterns []*regexp.Regexp) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// sendDenyResponse sends a deny response with the specified code and message
func sendDenyResponse(code int, message string) {
	var statusCode uint32 = uint32(code)

	// Build OpenAI-compatible error response
	errorResponse := buildErrorResponse(message)

	headers := [][2]string{
		{"content-type", "application/json"},
	}

	proxywasm.SendHttpResponse(statusCode, headers, []byte(errorResponse), -1)
}

// buildErrorResponse builds an OpenAI-compatible error response
func buildErrorResponse(message string) string {
	// Escape special characters for JSON
	escapedMessage := strings.ReplaceAll(message, "\"", "\\\"")
	escapedMessage = strings.ReplaceAll(escapedMessage, "\n", "\\n")

	return `{"error":{"message":"` + escapedMessage + `","type":"prompt_guard_error","code":"content_blocked"}}`
}

// SecurityEvent 安全事件（与 ai-agent-guard 的 SecurityEvent 结构对齐）
type SecurityEvent struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	Score       int    `json:"score"`
	Detail      string `json:"detail"`
	Direction   string `json:"direction"` // "request" = 命中于请求体；"response" = 命中于响应体
	HitContent  string `json:"hit_content"`
	RuleName    string `json:"rule_name"`
	RuleGroup   string `json:"rule_group"`
	MatchMethod string `json:"match_method"`
	MatchedText string `json:"matched_text"`
	Reason      string `json:"reason"`
	DetectMode  string `json:"detect_mode"`
	Blocked     bool   `json:"blocked"`
	TimestampMs int64  `json:"timestamp_ms"`
}

// emitSecurityEvent 把命中事件写入 wasm.ai_log 一级 filter state。
// 两级路径 security_events 属于插件私有 VM，ai-agent-guard 读不到；ai_log 是
// per-request 共享状态，WriteUserAttributeToLogWithKey 会先读回已有 key 再 merge，
// 因此不会覆盖其它插件写入的 agent_guard_audit / api 等字段。
func emitSecurityEvent(ctx wrapper.HttpContext, event SecurityEvent) {
	var events []SecurityEvent
	if existing, ok := ctx.GetUserAttribute(PromptGuardEventKey).(string); ok && existing != "" {
		_ = json.Unmarshal([]byte(existing), &events)
	}
	if len(events) >= maxEmittedEvents {
		log.Warnf("prompt guard events exceed %d, drop new hit", maxEmittedEvents)
		return
	}
	events = append(events, event)
	data, err := json.Marshal(events)
	if err != nil {
		log.Warnf("marshal security events failed: %v", err)
		return
	}
	// 事件数组整体也要有上界：保留最新命中、丢弃最旧，防止多条大命中叠加
	// 把 wasm.ai_log（以及由它生成的单行 access log）撑到几十 KB。
	for len(events) > 1 && len(data) > maxAIlogEventBytes {
		events = events[1:]
		data, err = json.Marshal(events)
		if err != nil {
			log.Warnf("marshal security events failed: %v", err)
			return
		}
	}
	ctx.SetUserAttribute(PromptGuardEventKey, string(data))
	if err := ctx.WriteUserAttributeToLogWithKey(wrapper.AILogKey); err != nil {
		log.Warnf("write %s to ai_log failed: %v", PromptGuardEventKey, err)
	}
}
