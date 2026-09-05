package mitmproxy

import "testing"

func TestUpstreamHTTPTraceOptionIsOptIn(t *testing.T) {
	if newOptions().upstreamHTTPTrace {
		t.Fatal("upstream HTTP trace enabled by default")
	}
	if !newOptions(WithUpstreamHTTPTrace()).upstreamHTTPTrace {
		t.Fatal("WithUpstreamHTTPTrace did not enable tracing")
	}
}
