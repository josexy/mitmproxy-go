//go:build windows

package mitmproxy

import (
	"math/bits"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32Timing                = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter   = kernel32Timing.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = kernel32Timing.NewProc("QueryPerformanceFrequency")
	performanceFrequencyOnce      sync.Once
	performanceFrequencyValue     int64
	performanceFrequencyAvailable bool
)

type qpcTimingClock struct {
	baseWall    time.Time
	baseCounter int64
	frequency   int64
	readCounter func() (int64, bool)
}

func newTimingClock() timingClock {
	frequency, ok := performanceFrequency()
	if !ok {
		return systemTimingClock{}
	}
	before, ok := readPerformanceCounter()
	if !ok {
		return systemTimingClock{}
	}
	// Strip Go's coarse Windows monotonic reading. Every value returned by this
	// clock is derived from the QPC counter instead, so it must not be compared
	// through an unrelated monotonic component.
	baseWall := time.Now().Round(0)
	after, ok := readPerformanceCounter()
	if !ok || after < before {
		return systemTimingClock{}
	}

	return &qpcTimingClock{
		baseWall:    baseWall,
		baseCounter: before + (after-before)/2,
		frequency:   frequency,
		readCounter: readPerformanceCounter,
	}
}

func performanceFrequency() (int64, bool) {
	performanceFrequencyOnce.Do(func() {
		if err := procQueryPerformanceCounter.Find(); err != nil {
			return
		}
		if err := procQueryPerformanceFrequency.Find(); err != nil {
			return
		}
		frequency, ok := readPerformanceFrequency()
		if !ok || frequency <= 0 {
			return
		}
		performanceFrequencyValue = frequency
		performanceFrequencyAvailable = true
	})
	return performanceFrequencyValue, performanceFrequencyAvailable
}

func (c *qpcTimingClock) Now() time.Time {
	counter, ok := c.readCounter()
	if !ok || counter <= c.baseCounter {
		return c.baseWall
	}
	return c.baseWall.Add(qpcTicksToDuration(counter-c.baseCounter, c.frequency))
}

func readPerformanceCounter() (int64, bool) {
	return readPerformanceValue(procQueryPerformanceCounter)
}

func readPerformanceFrequency() (int64, bool) {
	return readPerformanceValue(procQueryPerformanceFrequency)
}

func readPerformanceValue(proc *windows.LazyProc) (int64, bool) {
	var value int64
	result, _, _ := proc.Call(uintptr(unsafe.Pointer(&value)))
	return value, result != 0
}

func qpcTicksToDuration(delta, frequency int64) time.Duration {
	if delta <= 0 || frequency <= 0 {
		return 0
	}

	const maxDuration = time.Duration(1<<63 - 1)
	seconds := delta / frequency
	if seconds > int64(maxDuration/time.Second) {
		return maxDuration
	}
	remainder := delta % frequency
	hi, lo := bits.Mul64(uint64(remainder), uint64(time.Second))
	nanoseconds, _ := bits.Div64(hi, lo, uint64(frequency))
	wholeSeconds := time.Duration(seconds) * time.Second
	if time.Duration(nanoseconds) > maxDuration-wholeSeconds {
		return maxDuration
	}
	return wholeSeconds + time.Duration(nanoseconds)
}
