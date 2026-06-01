package metadata

import (
	"context"
	"maps"
	"sync"
	"time"
)

// metadataKey is the context key for storing metadata in context.Context
type metadataKey struct{}

type metadata struct {
	mu sync.RWMutex

	setFields uint32

	streamBody                    bool
	localConnectionEstablishedTs  time.Time
	remoteConnectionEstablishedTs time.Time
	requestReceivedTs             time.Time
	dnsLookupStartTs              time.Time
	dnsLookupDoneTs               time.Time
	socketConnectStartTs          time.Time
	socketConnectDoneTs           time.Time
	sslHandshakeStartTs           time.Time
	sslHandshakeCompletedTs       time.Time
	requestUploadStartTs          time.Time
	requestUploadDoneTs           time.Time
	responseStartTs               time.Time
	responseDoneTs                time.Time
	connectionReused              bool
	requestHostport               string
	localConnectionAddrInfo       ConnectionAddrInfo
	remoteConnectionAddrInfo      ConnectionAddrInfo
	tlsState                      *TLSState
	serverCertificate             *ServerCertificate

	extra map[string]any
}

const (
	fieldStreamBody uint32 = 1 << iota
	fieldLocalConnectionEstablishedTs
	fieldRemoteConnectionEstablishedTs
	fieldRequestReceivedTs
	fieldDNSLookupStartTs
	fieldDNSLookupDoneTs
	fieldSocketConnectStartTs
	fieldSocketConnectDoneTs
	fieldSSLHandshakeStartTs
	fieldSSLHandshakeCompletedTs
	fieldRequestUploadStartTs
	fieldRequestUploadDoneTs
	fieldResponseStartTs
	fieldResponseDoneTs
	fieldConnectionReused
	fieldRequestHostport
	fieldLocalConnectionAddrInfo
	fieldRemoteConnectionAddrInfo
	fieldConnectionTLSState
	fieldConnectionServerCertificate
)

func NewMD() *metadata { return &metadata{} }

func (m *metadata) Set(key string, val any) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch key {
	case StreamBody:
		if v, ok := val.(bool); ok {
			m.streamBody = v
			m.setKnownField(key, fieldStreamBody)
			return
		}
	case LocalConnectionEstablishedTs:
		if v, ok := val.(time.Time); ok {
			m.localConnectionEstablishedTs = v
			m.setKnownField(key, fieldLocalConnectionEstablishedTs)
			return
		}
	case RemoteConnectionEstablishedTs:
		if v, ok := val.(time.Time); ok {
			m.remoteConnectionEstablishedTs = v
			m.setKnownField(key, fieldRemoteConnectionEstablishedTs)
			return
		}
	case RequestReceivedTs:
		if v, ok := val.(time.Time); ok {
			m.requestReceivedTs = v
			m.setKnownField(key, fieldRequestReceivedTs)
			return
		}
	case DNSLookupStartTs:
		if v, ok := val.(time.Time); ok {
			m.dnsLookupStartTs = v
			m.setKnownField(key, fieldDNSLookupStartTs)
			return
		}
	case DNSLookupDoneTs:
		if v, ok := val.(time.Time); ok {
			m.dnsLookupDoneTs = v
			m.setKnownField(key, fieldDNSLookupDoneTs)
			return
		}
	case SocketConnectStartTs:
		if v, ok := val.(time.Time); ok {
			m.socketConnectStartTs = v
			m.setKnownField(key, fieldSocketConnectStartTs)
			return
		}
	case SocketConnectDoneTs:
		if v, ok := val.(time.Time); ok {
			m.socketConnectDoneTs = v
			m.setKnownField(key, fieldSocketConnectDoneTs)
			return
		}
	case SSLHandshakeStartTs:
		if v, ok := val.(time.Time); ok {
			m.sslHandshakeStartTs = v
			m.setKnownField(key, fieldSSLHandshakeStartTs)
			return
		}
	case SSLHandshakeCompletedTs:
		if v, ok := val.(time.Time); ok {
			m.sslHandshakeCompletedTs = v
			m.setKnownField(key, fieldSSLHandshakeCompletedTs)
			return
		}
	case RequestUploadStartTs:
		if v, ok := val.(time.Time); ok {
			m.requestUploadStartTs = v
			m.setKnownField(key, fieldRequestUploadStartTs)
			return
		}
	case RequestUploadDoneTs:
		if v, ok := val.(time.Time); ok {
			m.requestUploadDoneTs = v
			m.setKnownField(key, fieldRequestUploadDoneTs)
			return
		}
	case ResponseStartTs:
		if v, ok := val.(time.Time); ok {
			m.responseStartTs = v
			m.setKnownField(key, fieldResponseStartTs)
			return
		}
	case ResponseDoneTs:
		if v, ok := val.(time.Time); ok {
			m.responseDoneTs = v
			m.setKnownField(key, fieldResponseDoneTs)
			return
		}
	case ConnectionReused:
		if v, ok := val.(bool); ok {
			m.connectionReused = v
			m.setKnownField(key, fieldConnectionReused)
			return
		}
	case RequestHostport:
		if v, ok := val.(string); ok {
			m.requestHostport = v
			m.setKnownField(key, fieldRequestHostport)
			return
		}
	case LocalConnectionAddrInfo:
		if v, ok := val.(ConnectionAddrInfo); ok {
			m.localConnectionAddrInfo = v
			m.setKnownField(key, fieldLocalConnectionAddrInfo)
			return
		}
	case RemoteConnectionAddrInfo:
		if v, ok := val.(ConnectionAddrInfo); ok {
			m.remoteConnectionAddrInfo = v
			m.setKnownField(key, fieldRemoteConnectionAddrInfo)
			return
		}
	case ConnectionTLSState:
		if v, ok := val.(*TLSState); ok {
			m.tlsState = v
			m.setKnownField(key, fieldConnectionTLSState)
			return
		}
	case ConnectionServerCertificate:
		if v, ok := val.(*ServerCertificate); ok {
			m.serverCertificate = v
			m.setKnownField(key, fieldConnectionServerCertificate)
			return
		}
	}

	m.clearKnownField(key)
	if m.extra == nil {
		m.extra = make(map[string]any)
	}
	m.extra[key] = val
}

func (m *metadata) setKnownField(key string, field uint32) {
	m.setFields |= field
	if m.extra != nil {
		delete(m.extra, key)
	}
}

func (m *metadata) clearKnownField(key string) {
	switch key {
	case StreamBody:
		m.setFields &^= fieldStreamBody
	case LocalConnectionEstablishedTs:
		m.setFields &^= fieldLocalConnectionEstablishedTs
	case RemoteConnectionEstablishedTs:
		m.setFields &^= fieldRemoteConnectionEstablishedTs
	case RequestReceivedTs:
		m.setFields &^= fieldRequestReceivedTs
	case DNSLookupStartTs:
		m.setFields &^= fieldDNSLookupStartTs
	case DNSLookupDoneTs:
		m.setFields &^= fieldDNSLookupDoneTs
	case SocketConnectStartTs:
		m.setFields &^= fieldSocketConnectStartTs
	case SocketConnectDoneTs:
		m.setFields &^= fieldSocketConnectDoneTs
	case SSLHandshakeStartTs:
		m.setFields &^= fieldSSLHandshakeStartTs
	case SSLHandshakeCompletedTs:
		m.setFields &^= fieldSSLHandshakeCompletedTs
	case RequestUploadStartTs:
		m.setFields &^= fieldRequestUploadStartTs
	case RequestUploadDoneTs:
		m.setFields &^= fieldRequestUploadDoneTs
	case ResponseStartTs:
		m.setFields &^= fieldResponseStartTs
	case ResponseDoneTs:
		m.setFields &^= fieldResponseDoneTs
	case ConnectionReused:
		m.setFields &^= fieldConnectionReused
	case RequestHostport:
		m.setFields &^= fieldRequestHostport
	case LocalConnectionAddrInfo:
		m.setFields &^= fieldLocalConnectionAddrInfo
	case RemoteConnectionAddrInfo:
		m.setFields &^= fieldRemoteConnectionAddrInfo
	case ConnectionTLSState:
		m.setFields &^= fieldConnectionTLSState
	case ConnectionServerCertificate:
		m.setFields &^= fieldConnectionServerCertificate
	}
}

func (m *metadata) Get(key string) (val any, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch key {
	case StreamBody:
		if m.setFields&fieldStreamBody == 0 {
			return m.getExtra(key)
		}
		return m.streamBody, true
	case LocalConnectionEstablishedTs:
		if m.setFields&fieldLocalConnectionEstablishedTs == 0 {
			return m.getExtra(key)
		}
		return m.localConnectionEstablishedTs, true
	case RemoteConnectionEstablishedTs:
		if m.setFields&fieldRemoteConnectionEstablishedTs == 0 {
			return m.getExtra(key)
		}
		return m.remoteConnectionEstablishedTs, true
	case RequestReceivedTs:
		if m.setFields&fieldRequestReceivedTs == 0 {
			return m.getExtra(key)
		}
		return m.requestReceivedTs, true
	case DNSLookupStartTs:
		if m.setFields&fieldDNSLookupStartTs == 0 {
			return m.getExtra(key)
		}
		return m.dnsLookupStartTs, true
	case DNSLookupDoneTs:
		if m.setFields&fieldDNSLookupDoneTs == 0 {
			return m.getExtra(key)
		}
		return m.dnsLookupDoneTs, true
	case SocketConnectStartTs:
		if m.setFields&fieldSocketConnectStartTs == 0 {
			return m.getExtra(key)
		}
		return m.socketConnectStartTs, true
	case SocketConnectDoneTs:
		if m.setFields&fieldSocketConnectDoneTs == 0 {
			return m.getExtra(key)
		}
		return m.socketConnectDoneTs, true
	case SSLHandshakeStartTs:
		if m.setFields&fieldSSLHandshakeStartTs == 0 {
			return m.getExtra(key)
		}
		return m.sslHandshakeStartTs, true
	case SSLHandshakeCompletedTs:
		if m.setFields&fieldSSLHandshakeCompletedTs == 0 {
			return m.getExtra(key)
		}
		return m.sslHandshakeCompletedTs, true
	case RequestUploadStartTs:
		if m.setFields&fieldRequestUploadStartTs == 0 {
			return m.getExtra(key)
		}
		return m.requestUploadStartTs, true
	case RequestUploadDoneTs:
		if m.setFields&fieldRequestUploadDoneTs == 0 {
			return m.getExtra(key)
		}
		return m.requestUploadDoneTs, true
	case ResponseStartTs:
		if m.setFields&fieldResponseStartTs == 0 {
			return m.getExtra(key)
		}
		return m.responseStartTs, true
	case ResponseDoneTs:
		if m.setFields&fieldResponseDoneTs == 0 {
			return m.getExtra(key)
		}
		return m.responseDoneTs, true
	case ConnectionReused:
		if m.setFields&fieldConnectionReused == 0 {
			return m.getExtra(key)
		}
		return m.connectionReused, true
	case RequestHostport:
		if m.setFields&fieldRequestHostport == 0 {
			return m.getExtra(key)
		}
		return m.requestHostport, true
	case LocalConnectionAddrInfo:
		if m.setFields&fieldLocalConnectionAddrInfo == 0 {
			return m.getExtra(key)
		}
		return m.localConnectionAddrInfo, true
	case RemoteConnectionAddrInfo:
		if m.setFields&fieldRemoteConnectionAddrInfo == 0 {
			return m.getExtra(key)
		}
		return m.remoteConnectionAddrInfo, true
	case ConnectionTLSState:
		if m.setFields&fieldConnectionTLSState == 0 {
			return m.getExtra(key)
		}
		return m.tlsState, true
	case ConnectionServerCertificate:
		if m.setFields&fieldConnectionServerCertificate == 0 {
			return m.getExtra(key)
		}
		return m.serverCertificate, true
	default:
		return m.getExtra(key)
	}
}

func (m *metadata) getExtra(key string) (any, bool) {
	if m.extra == nil {
		return nil, false
	}
	val, ok := m.extra[key]
	return val, ok
}

func (m *metadata) MD() MD {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var md MD
	if m.setFields&fieldStreamBody != 0 {
		md.StreamBody = m.streamBody
	}
	if m.setFields&fieldLocalConnectionEstablishedTs != 0 {
		md.LocalConnectionEstablishedTs = m.localConnectionEstablishedTs
	}
	if m.setFields&fieldRemoteConnectionEstablishedTs != 0 {
		md.RemoteConnectionEstablishedTs = m.remoteConnectionEstablishedTs
	}
	if m.setFields&fieldRequestReceivedTs != 0 {
		md.RequestProcessedTs = m.requestReceivedTs
	}
	if m.setFields&fieldSSLHandshakeStartTs != 0 {
		md.SSLHandshakeStartTs = m.sslHandshakeStartTs
	}
	if m.setFields&fieldSSLHandshakeCompletedTs != 0 {
		md.SSLHandshakeCompletedTs = m.sslHandshakeCompletedTs
	}
	if m.setFields&fieldRequestHostport != 0 {
		md.RequestHostport = m.requestHostport
	}
	if m.setFields&fieldLocalConnectionAddrInfo != 0 {
		md.LocalAddrInfo = m.localConnectionAddrInfo
	}
	if m.setFields&fieldRemoteConnectionAddrInfo != 0 {
		md.RemoteAddrInfo = m.remoteConnectionAddrInfo
	}
	if m.setFields&fieldConnectionTLSState != 0 {
		md.TLSState = m.tlsState
	}
	if m.setFields&fieldConnectionServerCertificate != 0 {
		md.ServerCertificate = m.serverCertificate
	}
	md.Timing = buildTiming(timingMarks{
		Start:              m.requestReceivedTs,
		End:                m.responseDoneTs,
		DNSLookupStart:     m.dnsLookupStartTs,
		DNSLookupDone:      m.dnsLookupDoneTs,
		SocketConnectStart: m.socketConnectStartTs,
		SocketConnectDone:  m.socketConnectDoneTs,
		SSLHandshakeStart:  m.sslHandshakeStartTs,
		SSLHandshakeDone:   m.sslHandshakeCompletedTs,
		RequestUploadStart: m.requestUploadStartTs,
		RequestUploadDone:  m.requestUploadDoneTs,
		ResponseStart:      m.responseStartTs,
		ResponseDone:       m.responseDoneTs,
		ConnectionReused:   m.connectionReused,
	})
	return md
}

func AppendToContext(ctx context.Context, md *metadata) context.Context {
	return context.WithValue(ctx, metadataKey{}, md)
}

func FromContext(ctx context.Context) (*metadata, bool) {
	md, ok := ctx.Value(metadataKey{}).(*metadata)
	if !ok {
		return nil, false
	}
	return md, true
}

func (m *metadata) Clone() *metadata {
	m.mu.RLock()
	defer m.mu.RUnlock()

	dst := &metadata{
		setFields:                     m.setFields,
		streamBody:                    m.streamBody,
		localConnectionEstablishedTs:  m.localConnectionEstablishedTs,
		remoteConnectionEstablishedTs: m.remoteConnectionEstablishedTs,
		requestReceivedTs:             m.requestReceivedTs,
		dnsLookupStartTs:              m.dnsLookupStartTs,
		dnsLookupDoneTs:               m.dnsLookupDoneTs,
		socketConnectStartTs:          m.socketConnectStartTs,
		socketConnectDoneTs:           m.socketConnectDoneTs,
		sslHandshakeStartTs:           m.sslHandshakeStartTs,
		sslHandshakeCompletedTs:       m.sslHandshakeCompletedTs,
		requestUploadStartTs:          m.requestUploadStartTs,
		requestUploadDoneTs:           m.requestUploadDoneTs,
		responseStartTs:               m.responseStartTs,
		responseDoneTs:                m.responseDoneTs,
		connectionReused:              m.connectionReused,
		requestHostport:               m.requestHostport,
		localConnectionAddrInfo:       m.localConnectionAddrInfo,
		remoteConnectionAddrInfo:      m.remoteConnectionAddrInfo,
		tlsState:                      m.tlsState,
		serverCertificate:             m.serverCertificate,
	}
	if len(m.extra) > 0 {
		dst.extra = make(map[string]any, len(m.extra))
		maps.Copy(dst.extra, m.extra)
	}
	return dst
}

func (m *metadata) SetStreamBody(v bool) {
	m.mu.Lock()
	m.streamBody = v
	m.setKnownField(StreamBody, fieldStreamBody)
	m.mu.Unlock()
}

func (m *metadata) SetLocalConnectionEstablishedTs(v time.Time) {
	m.mu.Lock()
	m.localConnectionEstablishedTs = v
	m.setKnownField(LocalConnectionEstablishedTs, fieldLocalConnectionEstablishedTs)
	m.mu.Unlock()
}

func (m *metadata) SetRemoteConnectionEstablishedTs(v time.Time) {
	m.mu.Lock()
	m.remoteConnectionEstablishedTs = v
	m.setKnownField(RemoteConnectionEstablishedTs, fieldRemoteConnectionEstablishedTs)
	m.mu.Unlock()
}

func (m *metadata) SetRequestReceivedTs(v time.Time) {
	m.mu.Lock()
	m.requestReceivedTs = v
	m.setKnownField(RequestReceivedTs, fieldRequestReceivedTs)
	m.mu.Unlock()
}

func (m *metadata) SetDNSLookupStartTs(v time.Time) {
	m.mu.Lock()
	m.dnsLookupStartTs = v
	m.setKnownField(DNSLookupStartTs, fieldDNSLookupStartTs)
	m.mu.Unlock()
}

func (m *metadata) SetDNSLookupDoneTs(v time.Time) {
	m.mu.Lock()
	m.dnsLookupDoneTs = v
	m.setKnownField(DNSLookupDoneTs, fieldDNSLookupDoneTs)
	m.mu.Unlock()
}

func (m *metadata) SetSocketConnectStartTs(v time.Time) {
	m.mu.Lock()
	m.socketConnectStartTs = v
	m.setKnownField(SocketConnectStartTs, fieldSocketConnectStartTs)
	m.mu.Unlock()
}

func (m *metadata) SetSocketConnectDoneTs(v time.Time) {
	m.mu.Lock()
	m.socketConnectDoneTs = v
	m.setKnownField(SocketConnectDoneTs, fieldSocketConnectDoneTs)
	m.mu.Unlock()
}

func (m *metadata) SetSSLHandshakeStartTs(v time.Time) {
	m.mu.Lock()
	m.sslHandshakeStartTs = v
	m.setKnownField(SSLHandshakeStartTs, fieldSSLHandshakeStartTs)
	m.mu.Unlock()
}

func (m *metadata) SetSSLHandshakeCompletedTs(v time.Time) {
	m.mu.Lock()
	m.sslHandshakeCompletedTs = v
	m.setKnownField(SSLHandshakeCompletedTs, fieldSSLHandshakeCompletedTs)
	m.mu.Unlock()
}

func (m *metadata) SetRequestUploadStartTs(v time.Time) {
	m.mu.Lock()
	m.requestUploadStartTs = v
	m.setKnownField(RequestUploadStartTs, fieldRequestUploadStartTs)
	m.mu.Unlock()
}

func (m *metadata) SetRequestUploadDoneTs(v time.Time) {
	m.mu.Lock()
	m.requestUploadDoneTs = v
	m.setKnownField(RequestUploadDoneTs, fieldRequestUploadDoneTs)
	m.mu.Unlock()
}

func (m *metadata) SetResponseStartTs(v time.Time) {
	m.mu.Lock()
	m.responseStartTs = v
	m.setKnownField(ResponseStartTs, fieldResponseStartTs)
	m.mu.Unlock()
}

func (m *metadata) SetResponseDoneTs(v time.Time) {
	m.mu.Lock()
	m.responseDoneTs = v
	m.setKnownField(ResponseDoneTs, fieldResponseDoneTs)
	m.mu.Unlock()
}

func (m *metadata) SetConnectionReused(v bool) {
	m.mu.Lock()
	m.connectionReused = v
	m.setKnownField(ConnectionReused, fieldConnectionReused)
	m.mu.Unlock()
}

func (m *metadata) SetRequestHostport(v string) {
	m.mu.Lock()
	m.requestHostport = v
	m.setKnownField(RequestHostport, fieldRequestHostport)
	m.mu.Unlock()
}

func (m *metadata) SetLocalConnectionAddrInfo(v ConnectionAddrInfo) {
	m.mu.Lock()
	m.localConnectionAddrInfo = v
	m.setKnownField(LocalConnectionAddrInfo, fieldLocalConnectionAddrInfo)
	m.mu.Unlock()
}

func (m *metadata) SetRemoteConnectionAddrInfo(v ConnectionAddrInfo) {
	m.mu.Lock()
	m.remoteConnectionAddrInfo = v
	m.setKnownField(RemoteConnectionAddrInfo, fieldRemoteConnectionAddrInfo)
	m.mu.Unlock()
}

func (m *metadata) SetConnectionTLSState(v *TLSState) {
	m.mu.Lock()
	m.tlsState = v
	m.setKnownField(ConnectionTLSState, fieldConnectionTLSState)
	m.mu.Unlock()
}

func (m *metadata) SetConnectionServerCertificate(v *ServerCertificate) {
	m.mu.Lock()
	m.serverCertificate = v
	m.setKnownField(ConnectionServerCertificate, fieldConnectionServerCertificate)
	m.mu.Unlock()
}
