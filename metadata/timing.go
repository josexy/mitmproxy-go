package metadata

import (
	"slices"
	"time"
)

type TimingPhaseName string

const (
	DNSLookup        TimingPhaseName = "dns_lookup"
	SocketConnect    TimingPhaseName = "socket_connect"
	SSLHandshake     TimingPhaseName = "ssl_handshake"
	RequestUpload    TimingPhaseName = "request_upload"
	WaitingResponse  TimingPhaseName = "waiting_response"
	ResponseDownload TimingPhaseName = "response_download"
	Other            TimingPhaseName = "other"
)

type Timing struct {
	Start            time.Time
	End              time.Time
	Total            time.Duration
	Phases           []TimingPhase
	Other            time.Duration
	ConnectionReused bool
}

type TimingPhase struct {
	Name     TimingPhaseName
	Start    time.Time
	End      time.Time
	Offset   time.Duration
	Duration time.Duration
}

type timingMarks struct {
	Start              time.Time
	End                time.Time
	DNSLookupStart     time.Time
	DNSLookupDone      time.Time
	SocketConnectStart time.Time
	SocketConnectDone  time.Time
	SSLHandshakeStart  time.Time
	SSLHandshakeDone   time.Time
	RequestUploadStart time.Time
	RequestUploadDone  time.Time
	ResponseStart      time.Time
	ResponseDone       time.Time
	ConnectionReused   bool
}

func buildTiming(marks timingMarks) Timing {
	start := firstNonZero(
		marks.Start,
		marks.DNSLookupStart,
		marks.SocketConnectStart,
		marks.SSLHandshakeStart,
		marks.RequestUploadStart,
		marks.ResponseStart,
		marks.ResponseDone,
	)
	end := lastNonZero(
		marks.End,
		marks.ResponseDone,
		marks.ResponseStart,
		marks.RequestUploadDone,
		marks.RequestUploadStart,
		marks.SSLHandshakeDone,
		marks.SocketConnectDone,
		marks.DNSLookupDone,
	)
	timing := Timing{
		Start:            start,
		End:              end,
		ConnectionReused: marks.ConnectionReused,
	}
	if !start.IsZero() && !end.IsZero() && !end.Before(start) {
		timing.Total = end.Sub(start)
	}

	addPhase := func(name TimingPhaseName, phaseStart, phaseEnd time.Time) {
		if phaseStart.IsZero() || phaseEnd.IsZero() || phaseEnd.Before(phaseStart) {
			return
		}
		phase := TimingPhase{
			Name:     name,
			Start:    phaseStart,
			End:      phaseEnd,
			Duration: phaseEnd.Sub(phaseStart),
		}
		if !start.IsZero() && !phaseStart.Before(start) {
			phase.Offset = phaseStart.Sub(start)
		}
		timing.Phases = append(timing.Phases, phase)
	}

	if !marks.ConnectionReused {
		addPhase(DNSLookup, marks.DNSLookupStart, marks.DNSLookupDone)
		addPhase(SocketConnect, marks.SocketConnectStart, marks.SocketConnectDone)
		addPhase(SSLHandshake, marks.SSLHandshakeStart, marks.SSLHandshakeDone)
	}
	addPhase(RequestUpload, marks.RequestUploadStart, marks.RequestUploadDone)
	addPhase(WaitingResponse, marks.RequestUploadDone, marks.ResponseStart)
	addPhase(ResponseDownload, marks.ResponseStart, marks.ResponseDone)

	slices.SortFunc(timing.Phases, func(a, b TimingPhase) int {
		return a.Start.Compare(b.Start)
	})

	timing.Phases, timing.Other = withOtherPhases(timing.Phases, start, end)
	return timing
}

func withOtherPhases(phases []TimingPhase, start, end time.Time) ([]TimingPhase, time.Duration) {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return phases, 0
	}
	var out []TimingPhase
	cursor := start
	var other time.Duration
	for _, phase := range phases {
		if phase.Start.After(cursor) {
			otherPhase := newTimingPhase(Other, cursor, phase.Start, start)
			other += otherPhase.Duration
			out = append(out, otherPhase)
		}
		out = append(out, phase)
		if phase.End.After(cursor) {
			cursor = phase.End
		}
	}
	if end.After(cursor) {
		otherPhase := newTimingPhase(Other, cursor, end, start)
		other += otherPhase.Duration
		out = append(out, otherPhase)
	}
	return out, other
}

func newTimingPhase(name TimingPhaseName, phaseStart, phaseEnd, timingStart time.Time) TimingPhase {
	phase := TimingPhase{
		Name:     name,
		Start:    phaseStart,
		End:      phaseEnd,
		Duration: phaseEnd.Sub(phaseStart),
	}
	if !timingStart.IsZero() && !phaseStart.Before(timingStart) {
		phase.Offset = phaseStart.Sub(timingStart)
	}
	return phase
}

func firstNonZero(times ...time.Time) time.Time {
	for _, ts := range times {
		if !ts.IsZero() {
			return ts
		}
	}
	return time.Time{}
}

func lastNonZero(times ...time.Time) time.Time {
	for _, ts := range times {
		if !ts.IsZero() {
			return ts
		}
	}
	return time.Time{}
}
