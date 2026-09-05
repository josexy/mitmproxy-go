//go:build !windows

package mitmproxy

func newTimingClock() timingClock {
	return systemTimingClock{}
}
