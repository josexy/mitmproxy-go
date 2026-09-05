package mitmproxy

import "time"

type timingClock interface {
	Now() time.Time
}

type systemTimingClock struct{}

func (systemTimingClock) Now() time.Time {
	return time.Now()
}
