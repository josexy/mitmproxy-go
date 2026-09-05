package mitmproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"

	"github.com/josexy/mitmproxy-go/v2/buf"
)

var (
	ErrInvalidSocks5Version     = errors.New("invalid socks5 version")
	ErrInvalidSocks5MethodCount = errors.New("invalid socks5 method count")
	ErrInvalidSocks5Address     = errors.New("invalid socks5 address")
	ErrUnsupportedSocks5Command = errors.New("unsupported socks5 command")
	ErrUnsupportedSocks5Auth    = errors.New("client did not offer socks5 no-authentication method")
	ErrInvalidSocks5Reserved    = errors.New("invalid socks5 reserved byte")
)

const (
	socks5ReplySucceeded              byte = 0x00
	socks5ReplyGeneralFailure         byte = 0x01
	socks5ReplyNetworkUnreachable     byte = 0x03
	socks5ReplyHostUnreachable        byte = 0x04
	socks5ReplyConnectionRefused      byte = 0x05
	socks5ReplyCommandNotSupported    byte = 0x07
	socks5ReplyAddressTypeUnsupported byte = 0x08
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
	if !bytes.Contains(buf.Slice(2, buf.Len()), []byte{0}) {
		if err := writeAll(conn, []byte{5, 0xff}); err != nil {
			return err
		}
		return ErrUnsupportedSocks5Auth
	}
	return writeAll(conn, []byte{5, 0})
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
	if buf.Byte(2) != 0 {
		_ = writeSocks5Reply(conn, socks5ReplyGeneralFailure, nil)
		return "", ErrInvalidSocks5Reserved
	}
	host, port, err := parseAddressForSocks5(conn, buf, 3)
	if err != nil {
		_ = writeSocks5Reply(conn, socks5ReplyAddressTypeUnsupported, nil)
		return "", err
	}
	if host == "" || port == 0 {
		_ = writeSocks5Reply(conn, socks5ReplyAddressTypeUnsupported, nil)
		return "", ErrInvalidSocks5Address
	}
	hostport := net.JoinHostPort(host, strconv.Itoa(int(port)))
	switch cmd {
	case 1: // connect
	default:
		if err := writeSocks5Reply(conn, socks5ReplyCommandNotSupported, nil); err != nil {
			return "", err
		}
		return "", ErrUnsupportedSocks5Command
	}
	return hostport, nil
}

func writeSocks5Reply(w io.Writer, reply byte, addr net.Addr) error {
	packet := []byte{5, reply, 0, 1, 0, 0, 0, 0, 0, 0}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr != nil {
		if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			copy(packet[4:8], ip4)
			binary.BigEndian.PutUint16(packet[8:10], uint16(tcpAddr.Port))
		} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
			packet = make([]byte, 22)
			packet[0], packet[1], packet[3] = 5, reply, 4
			copy(packet[4:20], ip6)
			binary.BigEndian.PutUint16(packet[20:22], uint16(tcpAddr.Port))
		}
	}
	return writeAll(w, packet)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func socks5ReplyForError(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return socks5ReplyConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return socks5ReplyNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return socks5ReplyHostUnreachable
	default:
		return socks5ReplyGeneralFailure
	}
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
