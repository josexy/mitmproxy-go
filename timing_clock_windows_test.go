//go:build windows

package mitmproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/v2/metadata"
)

func TestQPCTimingClockConvertsCounterTicks(t *testing.T) {
	base := time.Date(2026, time.August, 12, 20, 0, 0, 123_000_000, time.Local)
	counter := int64(1_000_000)
	clock := &qpcTimingClock{
		baseWall:    base,
		baseCounter: counter,
		frequency:   10_000_000,
		readCounter: func() (int64, bool) { return counter, true },
	}

	counter += 1_250
	if got, want := clock.Now(), base.Add(125*time.Microsecond); !got.Equal(want) {
		t.Fatalf("QPC time = %s, want %s", got, want)
	}
}

func TestWindowsDNSMetadataAdvancesInsideCoarseSystemTick(t *testing.T) {
	clock := newTimingClock()
	dialer := NewProxyDialer(nil, nil)
	dialer.ipResolver = testIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		start := clock.Now()
		for clock.Now().Sub(start) < 50*time.Microsecond {
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	ctx := withTimingClock(context.Background(), clock)
	for range 100 {
		coarseStart := time.Now().UnixNano()
		md := metadata.NewMD()
		if _, err := dialer.resolveTCPAddr(ctx, "tcp", "short.test:443", md); err != nil {
			t.Fatal(err)
		}
		if time.Now().UnixNano() == coarseStart {
			got := md.MD()
			if duration := got.DNSLookupCompletedTs.UnixMicro() - got.DNSLookupStartTs.UnixMicro(); duration < 50 {
				t.Fatalf("short DNS duration = %d microseconds", duration)
			}
			return
		}
	}
	t.Fatal("did not observe a DNS lookup within one coarse system tick")
}

func TestWindowsTimingClockAdvancesInsideCoarseSystemTick(t *testing.T) {
	clock := newTimingClock()
	if _, ok := clock.(*qpcTimingClock); !ok {
		t.Fatal("QueryPerformanceCounter clock unavailable")
	}

	for range 100 {
		coarseStart := time.Now().UnixNano()
		preciseStart := clock.Now()
		for range 100_000 {
			preciseEnd := clock.Now()
			if time.Now().UnixNano() != coarseStart {
				break
			}
			if preciseEnd.Sub(preciseStart) >= time.Microsecond {
				return
			}
		}
	}

	t.Fatal("QPC clock did not advance while time.Now remained on one system tick")
}
