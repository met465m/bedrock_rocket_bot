// rocket/conn.go
package rocket

import (
	"net"
	"time"
)

type Conn struct {
	UDP      *net.UDPConn
	Addr     *net.UDPAddr
	MTU      int
	Closed   bool
	CloseCh  chan struct{}
}

func Dial(addr string) (*Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		UDP:     conn,
		Addr:    udpAddr,
		MTU:     1400,
		CloseCh: make(chan struct{}),
	}

	return c, nil
}

func (c *Conn) Write(b []byte) error {
	if c.Closed {
		return nil
	}
	_, err := c.UDP.Write(b)
	return err
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.UDP.Read(b)
}

func (c *Conn) Close() {
	if c.Closed {
		return
	}
	c.Closed = true
	close(c.CloseCh)
	_ = c.UDP.Close()
}

