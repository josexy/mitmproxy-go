//go:build windows

package mitmproxy

import (
	"testing"
	"time"
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
