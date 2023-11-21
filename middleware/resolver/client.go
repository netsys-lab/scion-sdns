package resolver

// Originally this Client from github.com/miekg/dns
// Adapted for resolver package usage by Semih Alev.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/quic-go/quic-go"
)

const (
	headerSize = 12
)

// WARUM wird hier ein extra Conn geschrieben und nich der von miekg/dns benutzt ??

// A Conn represents a connection to a DNS server.
type Conn struct {
	net.Conn                // a net.Conn holding the connection
	UDPSize          uint16 // minimum receive buffer for UDP messages
	quicEarlySession *pan.QUICEarlySession
	quicSession      *pan.QUICSession
	qstream          quic.Stream
}

// Exchange performs a synchronous query
func (co *Conn) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {

	opt := m.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}

	if opt == nil && co.UDPSize < dns.MinMsgSize {
		co.UDPSize = dns.MinMsgSize
	}

	t := time.Now()

	if err = co.WriteMsg(m); err != nil {
		return nil, 0, err
	}

	r, err = co.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = dns.ErrId
	}

	rtt = time.Since(t)

	return r, rtt, err
}

// ReadMsg reads a message from the connection co.
// If the received message contains a TSIG record the transaction signature
// is verified. This method always tries to return the message, however if an
// error is returned there are no guarantees that the returned message is a
// valid representation of the packet read.
func (co *Conn) ReadMsg() (*dns.Msg, error) {
	var (
		p   []byte
		n   int
		err error
	)
	if isDoQ := co.qstream != nil; isDoQ {

		var msglength uint16
		if err := binary.Read(co.qstream, binary.BigEndian, &msglength); err != nil {
			return nil, err
		}
		p = AcquireBuf(msglength)

		// respBuf := p
		// var buff *bytes.Buffer = bytes.NewBuffer(respBuf)

		n, err = io.ReadFull(co.qstream, p)
		if err != nil {
			fmt.Printf("readFull failed: %v\n", err.Error())
			return nil, err
		}
		/*
			var bytesReadTotal int
			//n, err := stream.Read(respBuf)
			n, err := co.qstream.Read(buff.Bytes())
			// fmt.Printf("buffsize: %d\n", buff.Len())
			bytesReadTotal += n
			if err != nil && n == 0 {
				return nil, fmt.Errorf("reading response from %s: %w", co.quicEarlySession.RemoteAddr(), err)
			}
			// the fst two bytes of any message are a prefix containing the MessageLenght as UInt16(max. 65KB)
			var respLen []byte = respBuf[:2]
			var msglen uint16 = binary.BigEndian.Uint16(respLen)
			fmt.Printf("msglen from prefix: %d\n", msglen)

			//	fmt.Printf("%d bytes read on first read()\n", n)
			// var buflen int = len(respBuf)
			//fmt.Printf("size of readbuffer: %v\n", buflen)

			for msglen > uint16(bytesReadTotal) {
				//n2, err := stream.Read(respBuf)
				//var buf *bytes.Buffer
				//n2, err := stream.Read(buff.Bytes())
				n2, err := co.qstream.Read(buff.Bytes()[bytesReadTotal:])
				//fmt.Printf("%d buffsize\n", buff.Len())
				//respBuf =
				bytesReadTotal += n2
				//fmt.Printf("%d bytes read\n", n2)
				//fmt.Printf("%v bytesReadTotal\n", bytesReadTotal)

				if err != nil && n2 == 0 {
					return nil, fmt.Errorf("reading response from %s: %w", co.quicEarlySession.RemoteAddr(), err)
				}

			}

			// All DNS messages (queries and responses) sent over DoQ connections MUST
			// be encoded as a 2-octet length field followed by the message content as
			// specified in [RFC1035].
			// IMPORTANT: Note, that we ignore this prefix here as this implementation
			// does not support receiving multiple messages over a single connection.
			m = new(dns.Msg)

			err = m.Unpack(respBuf[2:]) // original
			// err = m.Unpack(response)
			if err != nil {
				return nil, fmt.Errorf("unpacking response from %s: %w", p.addr, err)
			}

			return m, nil
		*/
	} else {

		if _, ok := co.Conn.(net.PacketConn); ok {
			p = AcquireBuf(co.UDPSize)
			n, err = co.Read(p)
		} else {
			var length uint16
			if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
				return nil, err
			}

			p = AcquireBuf(length)
			n, err = io.ReadFull(co.Conn, p)
		}
	}
	// at this point the raw response message is read and contained in p

	if err != nil {
		return nil, err
	} else if n < headerSize {
		return nil, dns.ErrShortRead
	}

	defer ReleaseBuf(p)

	m := new(dns.Msg)
	if err := m.Unpack(p); err != nil {
		// If an error was returned, we still want to allow the user to use
		// the message, but naively they can just check err if they don't want
		// to use an erroneous message
		return m, err
	}
	return m, err
}

// Read implements the net.Conn read method.
func (co *Conn) Read(p []byte) (n int, err error) {
	if co.Conn == nil {
		return 0, dns.ErrConnEmpty
	}

	if _, ok := co.Conn.(net.PacketConn); ok {
		// UDP connection
		return co.Conn.Read(p)
	}

	var length uint16
	if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	if int(length) > len(p) {
		return 0, io.ErrShortBuffer
	}

	return io.ReadFull(co.Conn, p[:length])
}

// WriteMsg sends a message through the connection co.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *dns.Msg) (err error) {
	size := uint16(m.Len()) + 1

	out := AcquireBuf(size)
	defer ReleaseBuf(out)

	out, err = m.PackBuffer(out)
	if err != nil {
		return err
	}
	_, err = co.Write(out)
	return err
}

// AddPrefix adds a 2-byte prefix with the DNS message length.
func addPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}

// Write implements the net.Conn Write method.
func (co *Conn) Write(p []byte) (int, error) {
	if len(p) > dns.MaxMsgSize {
		return 0, errors.New("message too large")
	}

	// are we talking SCION DoQ here ?!
	var isDoQ, is0RTT bool = false, false
	if is0RTT = co.quicEarlySession != nil; is0RTT {
		isDoQ = true
	} else if co.quicSession != nil {
		isDoQ = true
	}
	var err error
	if isDoQ {
		var stream quic.Stream
		if is0RTT {
			stream, err = co.quicEarlySession.OpenStreamSync(context.Background())

		} else {
			stream, err = co.quicSession.OpenStreamSync(context.Background())
		}
		if err != nil {
			fmt.Printf("failed to open Stream: %v \n", err.Error())
		}

		rawMsg := addPrefix(p)
		if len(rawMsg) != len(p)+2 {
			fmt.Printf("Add prefix failed! len(rawMsg): %v\n", len(rawMsg))
		}
		var n int
		n, err = stream.Write(rawMsg)
		if err != nil {
			return n, fmt.Errorf("failed to write to a QUIC stream: %w", err)
		}
		if n != len(p)+2 {
			fmt.Printf("wrote %v but was supposed to write %v", n, len(p)+2)
		}

		// The client MUST send the DNS query over the selected stream, and MUST
		// indicate through the STREAM FIN mechanism that no further data will
		// be sent on that stream. Note, that stream.Close() closes the
		// write-direction of the stream, but does not prevent reading from it.
		_ = stream.Close()
		co.qstream = stream
		return n, nil

	}

	//----------------------------------------------------------

	if _, ok := co.Conn.(net.PacketConn); ok {
		return co.Conn.Write(p)
	}

	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(p)))

	n, err := (&net.Buffers{l, p}).WriteTo(co.Conn)
	return int(n), err
}

var bufferPool sync.Pool

// AcquireBuf returns an buf from pool
func AcquireBuf(size uint16) []byte {
	x := bufferPool.Get()
	if x == nil {
		return make([]byte, size)
	}
	buf := *(x.(*[]byte))
	if cap(buf) < int(size) {
		return make([]byte, size)
	}
	return buf[:size]
}

// ReleaseBuf returns buf to pool
func ReleaseBuf(buf []byte) {
	bufferPool.Put(&buf)
}
