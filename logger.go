package mitmproxy

import (
	"context"
	"log/slog"
	"net/http"
)

const logMessagePrefix = "[mitmproxy-go] "

var noopLogger = slog.New(noopSlogHandler{})

type noopSlogHandler struct{}

func (noopSlogHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (noopSlogHandler) Handle(context.Context, slog.Record) error { return nil }
func (noopSlogHandler) WithAttrs([]slog.Attr) slog.Handler        { return noopSlogHandler{} }
func (noopSlogHandler) WithGroup(string) slog.Handler             { return noopSlogHandler{} }

func normalizeLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return noopLogger
	}
	return logger
}

func loggerFromConfig(cfg *runtimeConfig) *slog.Logger {
	if cfg == nil {
		return noopLogger
	}
	return normalizeLogger(cfg.state.logger)
}

func loggerFromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return noopLogger
	}
	connCtx, ok := ctx.Value(connContextKey).(*biConnContext)
	if !ok || connCtx == nil {
		return noopLogger
	}
	return loggerFromConfig(connCtx.config)
}

func logAttrs(ctx context.Context, logger *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	logger = normalizeLogger(logger)
	if logger.Enabled(ctx, level) {
		logger.LogAttrs(ctx, level, logMessage(msg), attrs...)
	}
}

func logMessage(msg string) string {
	return logMessagePrefix + msg
}

func logConfigAttrs(ctx context.Context, cfg *runtimeConfig, level slog.Level, msg string, attrs ...slog.Attr) {
	logAttrs(ctx, loggerFromConfig(cfg), level, msg, attrs...)
}

func errorAttr(err error) slog.Attr {
	return namedErrorAttr("error", err)
}

func namedErrorAttr(name string, err error) slog.Attr {
	if err == nil {
		return slog.String(name, "")
	}
	return slog.String(name, err.Error())
}

func requestMethod(req *http.Request) string {
	if req == nil {
		return ""
	}
	return req.Method
}

func requestURL(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return req.URL.String()
}

func requestProto(req *http.Request) string {
	if req == nil {
		return ""
	}
	return req.Proto
}
