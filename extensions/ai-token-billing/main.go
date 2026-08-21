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
	"net/http"
	"strings"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/tokenusage"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/resp"
)

const (
	pluginName = "ai-token-billing"
)

func main() {}

func init() {
	wrapper.SetCtx(
		pluginName,
		wrapper.ParseConfig(parseConfig),
		wrapper.ProcessRequestHeaders(onHttpRequestHeaders),
		wrapper.ProcessStreamingResponseBody(onHttpStreamingResponseBody),
		wrapper.ProcessResponseBody(onHttpResponseBody),
	)
}

// RedisInfo contains Redis connection configuration
type RedisInfo struct {
	ServiceName string `json:"service_name"`
	ServicePort int    `json:"service_port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Timeout     int    `json:"timeout"`
	Database    int    `json:"database"`
}

// TokenBillingConfig contains configuration for token billing
type TokenBillingConfig struct {
	// Redis configuration
	RedisInfo RedisInfo `json:"redis"`
	// RedisKeyPrefix is the prefix for Redis keys
	RedisKeyPrefix string `json:"redis_key_prefix"`
	// ConsumerHeader is the header to identify the consumer
	ConsumerHeader string `json:"consumer_header"`
	// QuotaEnforcement enables/disables quota enforcement
	QuotaEnforcement bool `json:"quota_enforcement"`
	// DenyMessage is the message to return when quota is exceeded
	DenyMessage string `json:"deny_message"`
	// InputTokenMultiplier is the multiplier for input tokens (for pricing)
	InputTokenMultiplier float64 `json:"input_token_multiplier"`
	// OutputTokenMultiplier is the multiplier for output tokens (for pricing)
	OutputTokenMultiplier float64 `json:"output_token_multiplier"`
	// LogUsage enables usage logging
	LogUsage bool `json:"log_usage"`

	// Internal
	redisClient wrapper.RedisClient
}

func parseConfig(json gjson.Result, config *TokenBillingConfig) error {
	// Set defaults
	config.RedisKeyPrefix = "ai_token_billing:"
	config.ConsumerHeader = "x-mse-consumer"
	config.QuotaEnforcement = false
	config.DenyMessage = "Token quota exceeded"
	config.InputTokenMultiplier = 1.0
	config.OutputTokenMultiplier = 1.0
	config.LogUsage = true

	// Parse redis_key_prefix
	if json.Get("redis_key_prefix").Exists() {
		config.RedisKeyPrefix = json.Get("redis_key_prefix").String()
	}

	// Parse consumer_header
	if json.Get("consumer_header").Exists() {
		config.ConsumerHeader = json.Get("consumer_header").String()
	}

	// Parse quota_enforcement
	if json.Get("quota_enforcement").Exists() {
		config.QuotaEnforcement = json.Get("quota_enforcement").Bool()
	}

	// Parse deny_message
	if json.Get("deny_message").Exists() {
		config.DenyMessage = json.Get("deny_message").String()
	}

	// Parse input_token_multiplier
	if json.Get("input_token_multiplier").Exists() {
		config.InputTokenMultiplier = json.Get("input_token_multiplier").Float()
	}

	// Parse output_token_multiplier
	if json.Get("output_token_multiplier").Exists() {
		config.OutputTokenMultiplier = json.Get("output_token_multiplier").Float()
	}

	// Parse log_usage
	if json.Get("log_usage").Exists() {
		config.LogUsage = json.Get("log_usage").Bool()
	}

	// Parse Redis configuration
	redisConfig := json.Get("redis")
	if redisConfig.Exists() {
		serviceName := redisConfig.Get("service_name").String()
		if serviceName == "" {
			log.Warnf("Redis service_name is empty, token billing will be limited")
			return nil
		}

		servicePort := int(redisConfig.Get("service_port").Int())
		if servicePort == 0 {
			if strings.HasSuffix(serviceName, ".static") {
				servicePort = 80
			} else {
				servicePort = 6379
			}
		}

		username := redisConfig.Get("username").String()
		password := redisConfig.Get("password").String()
		timeout := int(redisConfig.Get("timeout").Int())
		if timeout == 0 {
			timeout = 1000
		}
		database := int(redisConfig.Get("database").Int())

		config.RedisInfo = RedisInfo{
			ServiceName: serviceName,
			ServicePort: servicePort,
			Username:    username,
			Password:    password,
			Timeout:     timeout,
			Database:    database,
		}

		config.redisClient = wrapper.NewRedisClusterClient(wrapper.FQDNCluster{
			FQDN: serviceName,
			Port: int64(servicePort),
		})

		return config.redisClient.Init(username, password, int64(timeout), wrapper.WithDataBase(database))
	}

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config TokenBillingConfig) types.Action {
	ctx.DisableReroute()

	// Get consumer identifier
	consumer, _ := proxywasm.GetHttpRequestHeader(config.ConsumerHeader)
	if consumer == "" {
		consumer = "anonymous"
	}
	ctx.SetContext("consumer", consumer)

	// Check quota if enforcement is enabled
	if config.QuotaEnforcement && config.redisClient != nil {
		config.redisClient.Get(config.RedisKeyPrefix+"quota:"+consumer, func(response resp.Value) {
			if err := response.Error(); err != nil {
				// No quota set, allow through
				proxywasm.ResumeHttpRequest()
				return
			}
			if response.IsNull() {
				// No quota set, allow through
				proxywasm.ResumeHttpRequest()
				return
			}
			quota := response.Integer()
			if quota <= 0 {
				sendDenyResponse(http.StatusForbidden, config.DenyMessage)
				return
			}
			proxywasm.ResumeHttpRequest()
		})
		return types.HeaderStopAllIterationAndWatermark
	}

	return types.ActionContinue
}

func onHttpStreamingResponseBody(ctx wrapper.HttpContext, config TokenBillingConfig, data []byte, endOfStream bool) []byte {
	// Extract token usage from streaming response
	if usage := tokenusage.GetTokenUsage(ctx, data); usage.TotalToken > 0 {
		ctx.SetContext(tokenusage.CtxKeyInputToken, usage.InputToken)
		ctx.SetContext(tokenusage.CtxKeyOutputToken, usage.OutputToken)
	}

	// Record usage at end of stream
	if endOfStream {
		recordTokenUsage(ctx, config)
	}

	return data
}

func onHttpResponseBody(ctx wrapper.HttpContext, config TokenBillingConfig, body []byte) types.Action {
	// Extract token usage from response
	if usage := tokenusage.GetTokenUsage(ctx, body); usage.TotalToken > 0 {
		ctx.SetContext(tokenusage.CtxKeyInputToken, usage.InputToken)
		ctx.SetContext(tokenusage.CtxKeyOutputToken, usage.OutputToken)
	}

	recordTokenUsage(ctx, config)

	return types.ActionContinue
}

func recordTokenUsage(ctx wrapper.HttpContext, config TokenBillingConfig) {
	// Get token counts
	inputToken, ok1 := ctx.GetContext(tokenusage.CtxKeyInputToken).(int64)
	outputToken, ok2 := ctx.GetContext(tokenusage.CtxKeyOutputToken).(int64)

	if !ok1 || !ok2 {
		return
	}

	// Calculate weighted tokens
	weightedInput := int64(float64(inputToken) * config.InputTokenMultiplier)
	weightedOutput := int64(float64(outputToken) * config.OutputTokenMultiplier)
	totalWeighted := weightedInput + weightedOutput

	// Get consumer
	consumer, _ := ctx.GetContext("consumer").(string)
	if consumer == "" {
		consumer = "anonymous"
	}

	// Log usage if enabled
	if config.LogUsage {
		log.Infof("Token usage - consumer=%s, input=%d, output=%d, weighted_total=%d",
			consumer, inputToken, outputToken, totalWeighted)
	}

	// Record to Redis if available
	if config.redisClient != nil {
		// Increment total usage
		config.redisClient.IncrBy(config.RedisKeyPrefix+"usage:"+consumer, int(totalWeighted), nil)

		// Increment input token count
		config.redisClient.IncrBy(config.RedisKeyPrefix+"input:"+consumer, int(inputToken), nil)

		// Increment output token count
		config.redisClient.IncrBy(config.RedisKeyPrefix+"output:"+consumer, int(outputToken), nil)

		// Decrement quota if enforcement is enabled
		if config.QuotaEnforcement {
			config.redisClient.DecrBy(config.RedisKeyPrefix+"quota:"+consumer, int(totalWeighted), nil)
		}
	}
}

func sendDenyResponse(code int, message string) {
	statusCode := uint32(code)

	// Build OpenAI-compatible error response
	escapedMessage := strings.ReplaceAll(message, "\"", "\\\"")
	escapedMessage = strings.ReplaceAll(escapedMessage, "\n", "\\n")

	errorResponse := `{"error":{"message":"` + escapedMessage + `","type":"quota_exceeded","code":"insufficient_quota"}}`

	headers := [][2]string{
		{"content-type", "application/json"},
	}

	proxywasm.SendHttpResponse(statusCode, headers, []byte(errorResponse), -1)
}

// GetTokenUsageStats retrieves token usage statistics for a consumer
func GetTokenUsageStats(redisClient wrapper.RedisClient, prefix string, consumer string) (input int64, output int64, total int64) {
	// This is a helper function for external use
	// In practice, this would be called by admin endpoints
	return 0, 0, 0
}
