# asg-wasm-plugins

ASG 自研 Higress WASM 插件仓库（解耦后独立发版）。

## 插件清单

| 插件 | 说明 |
|---|---|
| ai-agent-guard | AI 安全护栏（提示词注入防护、敏感信息、审计） |
| ai-context-manager | 上下文管理（摘要、FQDN 聚类、token 估算） |
| ai-pii-guard | PII 脱敏 |
| ai-prompt-guard | 提示词安全 |
| ai-token-billing | token 计费统计 |
| key-auth | 多凭据 Key 认证 |
| shadow-ai-detect | 影子 AI 检测 |
| sni-misdirect | SNI 重定向防护 |

## 构建

依赖：Docker（BuildKit）+ 远程 builder 镜像，无需本地 go/tinygo。

```bash
# 构建 wasm 到 extensions/<name>/plugin.wasm
make build PLUGIN_NAME=ai-pii-guard

# 构建镜像（默认推送到本地 registry 172.22.0.3:5000/plugins/）
make build-image PLUGIN_NAME=ai-pii-guard
make build-push PLUGIN_NAME=ai-pii-guard

# 生产 registry 覆盖
REGISTRY=registry.example.com/plugins/ make build-push PLUGIN_NAME=ai-pii-guard
```

## 测试

```bash
# 单元测试（在 builder 容器内执行）
docker run --rm -v $(pwd):/workspace -w /workspace/extensions/ai-pii-guard \
  higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/wasm-go-builder:go1.24.4-oras1.0.0 \
  go test ./...
```

## 纪律

- 本仓库为自研插件唯一开发位置；AISecGw 内禁止新增插件代码。
- WasmPlugin CR 配置放 `matchRules[].config`（`defaultConfig` 在存在 `_rules_` 时不参与合并）。
- 镜像 tag 语义化（如 1.0.15），与 WasmPlugin CR 引用保持一致。

## 网络代理说明

- 构建默认使用 goproxy.cn（国内可达）；如构建机已配置 go 环境则使用其 GOPROXY。
- 强制指定：`make build PLUGIN_NAME=<x> GOPROXY=https://goproxy.cn,direct`
