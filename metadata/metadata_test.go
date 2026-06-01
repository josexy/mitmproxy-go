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

func TestBuildTimingPhases(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	timing := buildTiming(timingMarks{
		Start:              base,
		End:                base.Add(25 * time.Millisecond),
		DNSLookupStart:     base.Add(1 * time.Millisecond),
		DNSLookupDone:      base.Add(3 * time.Millisecond),
		SocketConnectStart: base.Add(3 * time.Millisecond),
		SocketConnectDone:  base.Add(8 * time.Millisecond),
		SSLHandshakeStart:  base.Add(8 * time.Millisecond),
		SSLHandshakeDone:   base.Add(13 * time.Millisecond),
		RequestUploadStart: base.Add(15 * time.Millisecond),
		RequestUploadDone:  base.Add(16 * time.Millisecond),
		ResponseStart:      base.Add(21 * time.Millisecond),
		ResponseDone:       base.Add(24 * time.Millisecond),
	})

	if timing.Total != 25*time.Millisecond {
		t.Fatalf("Total = %s; want 25ms", timing.Total)
	}
	if timing.Other != 4*time.Millisecond {
		t.Fatalf("Other = %s; want 4ms", timing.Other)
	}
	for _, want := range []TimingPhaseName{DNSLookup, SocketConnect, SSLHandshake, RequestUpload, WaitingResponse, ResponseDownload, Other} {
		var found bool
		for _, phase := range timing.Phases {
			if phase.Name == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("timing missing phase %s: %#v", want, timing.Phases)
		}
	}
	for i := 1; i < len(timing.Phases); i++ {
		if timing.Phases[i].Start.Before(timing.Phases[i-1].End) {
			t.Fatalf("phase %d overlaps previous: %#v after %#v", i, timing.Phases[i], timing.Phases[i-1])
		}
	}
	dns := timing.Phases[1]
	if dns.Name != DNSLookup || dns.Offset != time.Millisecond || dns.Duration != 2*time.Millisecond {
		t.Fatalf("DNS phase = %#v; want offset 1ms duration 2ms", dns)
	}
}

func TestBuildTimingSkipsConnectionPhasesWhenReused(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	timing := buildTiming(timingMarks{
		Start:              base,
		End:                base.Add(10 * time.Millisecond),
		DNSLookupStart:     base,
		DNSLookupDone:      base.Add(time.Millisecond),
		SocketConnectStart: base.Add(time.Millisecond),
		SocketConnectDone:  base.Add(2 * time.Millisecond),
		RequestUploadStart: base.Add(3 * time.Millisecond),
		RequestUploadDone:  base.Add(4 * time.Millisecond),
		ResponseStart:      base.Add(6 * time.Millisecond),
		ResponseDone:       base.Add(8 * time.Millisecond),
		ConnectionReused:   true,
	})

	if !timing.ConnectionReused {
		t.Fatalf("ConnectionReused = false; want true")
	}
	for _, phase := range timing.Phases {
		if phase.Name == DNSLookup || phase.Name == SocketConnect || phase.Name == SSLHandshake {
			t.Fatalf("reused timing includes connection phase: %#v", phase)
		}
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
