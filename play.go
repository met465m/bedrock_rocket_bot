package bedrock_rocket_bot

import (
	"net"
	"time"
)

// Bot — основной объект бота
type Bot struct {
	Username string
	Conn     net.Conn
	Pos      Vector3
	Rot      Rotation
	Running  bool
}

// Vector3 — 3D-координаты
type Vector3 struct {
	X, Y, Z float64
}

// Rotation — направление взгляда
type Rotation struct {
	Yaw, Pitch float64
}

// NewBot создаёт нового бота
func NewBot(username string) *Bot {
	return &Bot{
		Username: username,
		Pos:      Vector3{X: 0, Y: 64, Z: 0},
		Rot:      Rotation{Yaw: 0, Pitch: 0},
		Running:  false,
	}
}

// Connect подключается к серверу и проходит handshake + login
func (b *Bot) Connect(addr string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	b.Conn = conn
	b.Running = true

	// Устанавливаем таймаут
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Handshake
	if err := Handshake(conn); err != nil {
		return err
	}

	// Login
	if err := Login(conn, b.Username); err != nil {
		return err
	}

	// Снимаем таймаут
	conn.SetDeadline(time.Time{})

	return nil
}

// Chat отправляет сообщение в чат
func (b *Bot) Chat(message string) error {
	packet := NewTextPacket(message)
	return SendPacket(b.Conn, packet)
}

// Move перемещает бота
func (b *Bot) Move(x, y, z float64) error {
	b.Pos = Vector3{X: x, Y: y, Z: z}
	packet := NewMovePacket(x, y, z)
	return SendPacket(b.Conn, packet)
}

// Close закрывает соединение
func (b *Bot) Close() {
	if b.Conn != nil {
		b.Conn.Close()
	}
	b.Running = false
}

