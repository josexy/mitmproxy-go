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

	setFields uint16

	streamBody                    bool
	localConnectionEstablishedTs  time.Time
	remoteConnectionEstablishedTs time.Time
	requestReceivedTs             time.Time
	dnsLookupStartTs              time.Time
	dnsLookupCompletedTs          time.Time
	socketConnectStartTs          time.Time
	socketConnectCompletedTs      time.Time
	sslHandshakeStartTs           time.Time
	sslHandshakeCompletedTs       time.Time
	requestHostport               string
	localConnectionAddrInfo       ConnectionAddrInfo
	remoteConnectionAddrInfo      ConnectionAddrInfo
	tlsState                      *TLSState
	serverCertificate             *ServerCertificate

	extra map[string]any
}

const (
	fieldStreamBody uint16 = 1 << iota
	fieldLocalConnectionEstablishedTs
	fieldRemoteConnectionEstablishedTs
	fieldRequestReceivedTs
	fieldDNSLookupStartTs
	fieldDNSLookupCompletedTs
	fieldSocketConnectStartTs
	fieldSocketConnectCompletedTs
	fieldSSLHandshakeStartTs
	fieldSSLHandshakeCompletedTs
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
	case DNSLookupCompletedTs:
		if v, ok := val.(time.Time); ok {
			m.dnsLookupCompletedTs = v
			m.setKnownField(key, fieldDNSLookupCompletedTs)
			return
		}
	case SocketConnectStartTs:
		if v, ok := val.(time.Time); ok {
			m.socketConnectStartTs = v
			m.setKnownField(key, fieldSocketConnectStartTs)
			return
		}
	case SocketConnectCompletedTs:
		if v, ok := val.(time.Time); ok {
			m.socketConnectCompletedTs = v
			m.setKnownField(key, fieldSocketConnectCompletedTs)
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

func (m *metadata) setKnownField(key string, field uint16) {
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
	case DNSLookupCompletedTs:
		m.setFields &^= fieldDNSLookupCompletedTs
	case SocketConnectStartTs:
		m.setFields &^= fieldSocketConnectStartTs
	case SocketConnectCompletedTs:
		m.setFields &^= fieldSocketConnectCompletedTs
	case SSLHandshakeStartTs:
		m.setFields &^= fieldSSLHandshakeStartTs
	case SSLHandshakeCompletedTs:
		m.setFields &^= fieldSSLHandshakeCompletedTs
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
	case DNSLookupCompletedTs:
		if m.setFields&fieldDNSLookupCompletedTs == 0 {
			return m.getExtra(key)
		}
		return m.dnsLookupCompletedTs, true
	case SocketConnectStartTs:
		if m.setFields&fieldSocketConnectStartTs == 0 {
			return m.getExtra(key)
		}
		return m.socketConnectStartTs, true
	case SocketConnectCompletedTs:
		if m.setFields&fieldSocketConnectCompletedTs == 0 {
			return m.getExtra(key)
		}
		return m.socketConnectCompletedTs, true
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
	if m.setFields&fieldDNSLookupStartTs != 0 {
		md.DNSLookupStartTs = m.dnsLookupStartTs
	}
	if m.setFields&fieldDNSLookupCompletedTs != 0 {
		md.DNSLookupCompletedTs = m.dnsLookupCompletedTs
	}
	if m.setFields&fieldSocketConnectStartTs != 0 {
		md.SocketConnectStartTs = m.socketConnectStartTs
	}
	if m.setFields&fieldSocketConnectCompletedTs != 0 {
		md.SocketConnectCompletedTs = m.socketConnectCompletedTs
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
		dnsLookupCompletedTs:          m.dnsLookupCompletedTs,
		socketConnectStartTs:          m.socketConnectStartTs,
		socketConnectCompletedTs:      m.socketConnectCompletedTs,
		sslHandshakeStartTs:           m.sslHandshakeStartTs,
		sslHandshakeCompletedTs:       m.sslHandshakeCompletedTs,
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

func (m *metadata) SetDNSLookupCompletedTs(v time.Time) {
	m.mu.Lock()
	m.dnsLookupCompletedTs = v
	m.setKnownField(DNSLookupCompletedTs, fieldDNSLookupCompletedTs)
	m.mu.Unlock()
}

func (m *metadata) SetSocketConnectStartTs(v time.Time) {
	m.mu.Lock()
	m.socketConnectStartTs = v
	m.setKnownField(SocketConnectStartTs, fieldSocketConnectStartTs)
	m.mu.Unlock()
}

func (m *metadata) SetSocketConnectCompletedTs(v time.Time) {
	m.mu.Lock()
	m.socketConnectCompletedTs = v
	m.setKnownField(SocketConnectCompletedTs, fieldSocketConnectCompletedTs)
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
