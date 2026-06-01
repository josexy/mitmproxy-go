package metadata

import (
	"testing"
	"time"
)

func TestMetadataTypedFieldsAndClone(t *testing.T) {
	md := NewMD()
	if got, ok := md.Get(StreamBody); ok || got != nil {
		t.Fatalf("unset known key = %v, %v; want nil, false", got, ok)
	}

	now := time.Now()
	md.SetStreamBody(true)
	md.SetLocalConnectionEstablishedTs(now)
	md.SetRequestHostport("example.com:443")
	md.Set("custom", "value")

	if got, ok := md.Get(StreamBody); !ok || got != true {
		t.Fatalf("Get(StreamBody) = %v, %v; want true, true", got, ok)
	}
	if got, ok := md.Get(RequestHostport); !ok || got != "example.com:443" {
		t.Fatalf("Get(RequestHostport) = %v, %v; want hostport, true", got, ok)
	}
	if got, ok := md.Get("custom"); !ok || got != "value" {
		t.Fatalf("Get(custom) = %v, %v; want value, true", got, ok)
	}

	md.Set(StreamBody, "not-bool")
	if got, ok := md.Get(StreamBody); !ok || got != "not-bool" {
		t.Fatalf("Get(StreamBody extra) = %v, %v; want not-bool, true", got, ok)
	}
	md.SetStreamBody(true)

	snapshot := md.MD()
	if !snapshot.StreamBody || !snapshot.LocalConnectionEstablishedTs.Equal(now) || snapshot.RequestHostport != "example.com:443" {
		t.Fatalf("MD snapshot mismatch: %#v", snapshot)
	}

	clone := md.Clone()
	md.SetRequestHostport("changed.example:443")
	md.Set("custom", "changed")
	if got := clone.MD().RequestHostport; got != "example.com:443" {
		t.Fatalf("clone RequestHostport = %q; want original", got)
	}
	if got, _ := clone.Get("custom"); got != "value" {
		t.Fatalf("clone custom = %v; want value", got)
	}
}

func BenchmarkMetadataSetKnownFields(b *testing.B) {
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		md := NewMD()
		md.SetLocalConnectionEstablishedTs(now)
		md.SetRemoteConnectionEstablishedTs(now)
		md.SetRequestReceivedTs(now)
		md.SetRequestHostport("example.com:443")
		md.SetLocalConnectionAddrInfo(ConnectionAddrInfo{})
		md.SetRemoteConnectionAddrInfo(ConnectionAddrInfo{})
		_ = md.MD()
	}
}
