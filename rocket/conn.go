package bedrock_rocket_bot

import (
	"net"
	"time"
)

// Connection — обёртка над UDP-соединением
type Connection struct {
	Conn       net.Conn
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Connected  bool
	Timeout    time.Duration
}

// NewConnection создаёт новое соединение с сервером
func NewConnection(addr string) (*Connection, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}

	return &Connection{
		Conn:       conn,
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: conn.RemoteAddr(),
		Connected:  true,
		Timeout:    10 * time.Second,
	}, nil
}

// SetTimeout устанавливает таймаут для операций
func (c *Connection) SetTimeout(d time.Duration) {
	c.Timeout = d
	c.Conn.SetDeadline(time.Now().Add(d))
}

// Close закрывает соединение
func (c *Connection) Close() error {
	c.Connected = false
	return c.Conn.Close()
}

// SendPacket отправляет пакет через соединение
func (c *Connection) SendPacket(data []byte) error {
	if !c.Connected {
		return ErrNotConnected
	}

	_, err := c.Conn.Write(data)
	return err
}

// ReceivePacket читает входящий пакет
func (c *Connection) ReceivePacket() ([]byte, error) {
	if !c.Connected {
		return nil, ErrNotConnected
	}

	c.SetTimeout(5 * time.Second)

	buf := make([]byte, 2048) // MTU для Bedrock
	n, err := c.Conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// IsConnected проверяет, активно ли соединение
func (c *Connection) IsConnected() bool {
	return c.Connected
}

// ErrNotConnected — ошибка при отсутствии соединения
var ErrNotConnected = &ConnectionError{"соединение не установлено"}

// ConnectionError — тип ошибки для соединения
type ConnectionError struct {
	msg string
}

func (e *ConnectionError) Error() string {
	return e.msg
}
