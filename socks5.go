package mitmproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/josexy/mitmproxy-go/buf"
)

var (
	ErrInvalidSocks5Version     = errors.New("invalid socks5 version")
	ErrInvalidSocks5MethodCount = errors.New("invalid socks5 method count")
	ErrInvalidSocks5Address     = errors.New("invalid socks5 address")
	ErrUnsupportedSocks5Command = errors.New("unsupported socks5 command")
)

func (r *mitmProxyHandler) handleSocks5Handshake(ctx context.Context, conn net.Conn) error {
	buf := acquireSocksBuffer()
	defer releaseSocksBuffer(buf)
	if _, err := buf.ReadFull(conn, 1); err != nil || buf.Byte(0) != 5 {
		return ErrInvalidSocks5Version
	}
	if _, err := buf.ReadFull(conn, 1); err != nil || buf.Byte(1) <= 0 {
		return ErrInvalidSocks5MethodCount
	}
	if _, err := buf.ReadFull(conn, int(buf.Byte(1))); err != nil {
		return err
	}
	// TODO: socks5 auth
	_, err := conn.Write([]byte{5, 0})
	return err
}

func (r *mitmProxyHandler) handleSocks5Request(ctx context.Context, conn net.Conn) (string, error) {
	buf := acquireSocksBuffer()
	defer releaseSocksBuffer(buf)
	if _, err := buf.ReadFull(conn, 1); err != nil || buf.Byte(0) != 5 {
		return "", ErrInvalidSocks5Version
	}
	if _, err := buf.ReadFull(conn, 2); err != nil {
		return "", err
	}
	cmd := buf.Byte(1)
	host, port, err := parseAddressForSocks5(conn, buf, 3)
	if err != nil {
		return "", err
	}
	hostport := net.JoinHostPort(host, strconv.Itoa(int(port)))
	switch cmd {
	case 1: // connect
		conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	default:
		// TODO: cmd 2: bind, 3: udp associate
		return "", ErrUnsupportedSocks5Command
	}
	return hostport, nil
}

func parseAddressForSocks5(r io.Reader, buf *buf.Buffer, offset int) (host string, port uint16, err error) {
	if _, err = buf.ReadFull(r, 1); err != nil {
		return
	}
	switch buf.Byte(offset) {
	case 0x3: // domain name
		if _, err = buf.ReadFull(r, 1); err != nil { // domain name length
			return
		}
		offset++
		n := int(buf.Byte(offset))
		if _, err = buf.ReadFull(r, n+2); err != nil { // domain name + port
			return
		}
		offset++
		host = string(buf.Slice(offset, offset+n))
		offset += n
		port = binary.BigEndian.Uint16(buf.Slice(offset, offset+2))
	case 0x1: // ipv4
		if _, err = buf.ReadFull(r, net.IPv4len+2); err != nil { // ipv4 + port
			return
		}
		offset++
		host = net.IP(buf.Slice(offset, offset+net.IPv4len)).String()
		offset += net.IPv4len
		port = binary.BigEndian.Uint16(buf.Slice(offset, offset+2))
	case 0x4: // ipv6
		if _, err = buf.ReadFull(r, net.IPv6len+2); err != nil { // ipv6 + port
			return
		}
		offset++
		host = net.IP(buf.Slice(offset, offset+net.IPv6len)).String()
		offset += net.IPv6len
		port = binary.BigEndian.Uint16(buf.Slice(offset, offset+2))
	default:
		err = ErrInvalidSocks5Address
	}
	return
}
