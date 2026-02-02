// net_control/connection.go
package net_control

import (
	"encoding/binary"
	"log"
	"net"
	"time"
)

const (
	OpenConnectionRequest1 = 0x05
	OpenConnectionReply1   = 0x06
	ConnectionRequest      = 0x09
	NewIncomingConnection  = 0x13
	Magic                  = "\xfe\xfd\x00\x00\x00\x00"
	MaxRetries             = 3
	Timeout                = 5 * time.Second
)

type Connection struct {
	UDPConn    *net.UDPConn
	ServerAddr *net.UDPAddr
	ClientGUID uint64
}

func Dial(serverAddr string) (*Connection, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	c := &Connection{
		UDPConn:    conn,
		ServerAddr: addr,
		ClientGUID: uint64(time.Now().UnixNano()),
	}

	log.Println("🚀 Начинаем handshake...")

	for i := 0; i < MaxRetries; i++ {
		err = c.handshake()
		if err == nil {
			log.Println("✅ Подключение установлено")
			return c, nil
		}
		log.Printf("🔁 Попытка %d не удалась: %v", i+1, err)
		time.Sleep(time.Second)
	}

	conn.Close()
	return nil, err
}

func (c *Connection) handshake() error {
	c.UDPConn.SetDeadline(time.Now().Add(Timeout))

	// Step 1: OpenConnectionRequest1
	req1 := []byte{OpenConnectionRequest1}
	req1 = append(req1, Magic...)
	req1 = append(req1, 0x00, 0x00) // MTU
	if _, err := c.UDPConn.Write(req1); err != nil {
		return err
	}

	// Step 2: Read OpenConnectionReply1
	buf := make([]byte, 2048)
	n, err := c.UDPConn.Read(buf)
	if err != nil {
		return err
	}
	if n < 17 || buf[0] != OpenConnectionReply1 {
		return &ErrInvalidPacket{Got: buf[0], Expected: OpenConnectionReply1}
	}

	// Step 3: ConnectionRequest
	connReq := []byte{ConnectionRequest}
	guidBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(guidBytes, c.ClientGUID)
	connReq = append(connReq, guidBytes...)
	connReq = append(connReq, 0x00)
	if _, err := c.UDPConn.Write(connReq); err != nil {
		return err
	}

	// Step 4: NewIncomingConnection
	n, err = c.UDPConn.Read(buf)
	if err != nil {
		return err
	}
	if n < 1 || buf[0] != NewIncomingConnection {
		return &ErrInvalidPacket{Got: buf[0], Expected: NewIncomingConnection}
	}

	c.UDPConn.SetDeadline(time.Time{})
	return nil
}

func (c *Connection) Write(data []byte) error {
	_, err := c.UDPConn.Write(data)
	return err
}

func (c *Connection) Read(data []byte) (int, error) {
	return c.UDPConn.Read(data)
}

func (c *Connection) Close() error {
	return c.UDPConn.Close()
}

type ErrInvalidPacket struct {
	Got, Expected byte
}

func (e *ErrInvalidPacket) Error() string {
	return "ожидал пакет 0x%x, получил 0x%x"
}
