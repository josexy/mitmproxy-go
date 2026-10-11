package mitmproxy

import (
	"context"
	"time"
)

type timingClockContextKey struct{}

// A connection's setup and exchanges must share one wall-time anchor. Separate
// QPC clocks anchored to coarse Windows system ticks can reorder short phases.
func withTimingClock(ctx context.Context, clock timingClock) context.Context {
	return context.WithValue(ctx, timingClockContextKey{}, clock)
}

func timingClockFromContext(ctx context.Context) timingClock {
	if clock, ok := ctx.Value(timingClockContextKey{}).(timingClock); ok && clock != nil {
		return clock
	}
	return newTimingClock()
}

type timingClock interface {
	Now() time.Time
}

type systemTimingClock struct{}

func (systemTimingClock) Now() time.Time {
	return time.Now()
}
