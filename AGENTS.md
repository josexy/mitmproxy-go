# AGENTS.md

## 项目与代码导航

Go 1.27+ 的 MITM 代理库，模块路径为 `github.com/josexy/mitmproxy-go/v2`；支持 HTTP、HTTPS、HTTP/2、h2c、WebSocket 和 SOCKS5。

- `mitm.go`、`socks5.go`：代理入口、协议分流与转发。
- `transport.go`、`http1_*`、`http2_*`、`h2c.go`：上游连接、HTTP 会话、流水线与协议适配。
- `tls_fingerprint.go`、`proxy_dialer.go`、`keycert_pool.go`：TLS 指纹、上游代理拨号与证书缓存。
- `option.go`、`runtime_config*.go`、`interceptor.go`：配置、动态更新与公开拦截器接口。
- `http_profile.go`、`http_trace_timing.go`、`metadata/`：线序元数据、交换计时与连接元数据。
- `buf/`、`internal/`：缓冲区、缓存、证书和流复制；`examples/`：调用示例，`examples/dumper/` 用于流量观察。

## 修改约定

- 先检查工作区和相关测试；只改任务相关内容，保留已有修改，不顺带做无关重构。
- 代理相关 HTTP 类型统一使用 `github.com/josexy/xhttp`，不可与 `net/http` 类型混用；自身包引用必须包含 `/v2`。
- 公开 API 或默认行为改变时，同步相关示例、测试和 README；新增注释说明约束与原因。
- 对改动的 Go 文件运行 `gofmt`，沿用现有命名与组织方式；依赖升级仅限任务需要。
- 未经明确要求，不暂存、提交、推送、打标签或修改相邻仓库。

## 关键行为约束

- 保持 Body 流式转发，不为保序而整包缓存；检查 EOF、取消、提前 Close 和错误路径中的 Body、连接、goroutine 及池化缓冲区释放。
- 线序元数据描述收到的流量，不能绕过逐跳头清理或覆盖拦截器修改；WebSocket 握手也遵循此规则。
- Trailer 的实际顺序在 Body EOF 后才能确定；首次 Hijack 后重新解析的 Body 也必须关联正确的 Trailer 元数据。
- HTTP/1 流水线保持响应顺序；HTTP/2 stream ID 属于各自连接，不直接重放跨连接的非根优先级依赖。
- 重试计时从退避、重连和写请求之前开始；写头前失败也算新尝试，旧尝试的回调不能污染新尝试。
- 动态配置以不可变快照发布，只影响新连接；拦截器与观察回调可能并发执行，共享状态必须同步。
- 核心日志不输出凭据、请求/响应正文、WebSocket 载荷或证书私钥；测试使用临时证书与本地服务。

## 验证

先跑相关回归测试，再按改动范围验证全库。协议与生命周期修复优先使用真实本地连接测试，覆盖受影响的流式、复用、取消或重试路径。

```bash
go test ./...
go test -race ./...
go vet ./...
go mod verify
go mod tidy -diff
git diff --check
```

纯文档改动检查内容、路径引用与差异即可，无需重跑 Go 测试。交付时说明修改、已验证项和未验证项；本地通过不等于远程 CI 已通过。
