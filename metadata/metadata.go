package metadata

import (
	"context"
	"sync"
	"time"
)

// metadataKey is the context key for storing metadata in context.Context
type metadataKey struct{}

type metadata struct {
	md sync.Map
}

func NewMD() *metadata { return &metadata{} }

func (m *metadata) Set(key string, val any) { m.md.Store(key, val) }

func (m *metadata) Get(key string) (val any, ok bool) { val, ok = m.md.Load(key); return }

func (m *metadata) get(key string) (val any) { val, _ = m.md.Load(key); return }

func (m *metadata) MD() MD {
	var md MD
	md.StreamBody, _ = m.get(StreamBody).(bool)
	md.LocalConnectionEstablishedTs, _ = m.get(LocalConnectionEstablishedTs).(time.Time)
	md.RemoteConnectionEstablishedTs, _ = m.get(RemoteConnectionEstablishedTs).(time.Time)
	md.RequestProcessedTs, _ = m.get(RequestReceivedTs).(time.Time)
	md.SSLHandshakeCompletedTs, _ = m.get(SSLHandshakeCompletedTs).(time.Time)
	md.RequestHostport, _ = m.get(RequestHostport).(string)
	md.LocalAddrInfo, _ = m.get(LocalConnectionAddrInfo).(ConnectionAddrInfo)
	md.RemoteAddrInfo, _ = m.get(RemoteConnectionAddrInfo).(ConnectionAddrInfo)
	md.TLSState, _ = m.get(ConnectionTLSState).(*TLSState)
	md.ServerCertificate, _ = m.get(ConnectionServerCertificate).(*ServerCertificate)
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
