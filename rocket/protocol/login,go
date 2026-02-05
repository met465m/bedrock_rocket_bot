package bedrock_rocket_bot

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Login отправляет пакет авторизации
func Login(conn net.Conn, username string) error {
	var packet []byte

	// Packet ID
	packet = append(packet, 0x01)

	// Protocol Version (например, 489 для 1.20.70)
	packet = append(packet, 0xe9, 0x01, 0x00, 0x00) // 489

	// Chain Data (заглушка)
	packet = WriteString(packet, "{}")

	// Skin Data (заглушка)
	packet = WriteString(packet, "{}")

	// Имя игрока
	packet = WriteString(packet, username)

	// Отправляем
	frame := NewFrame(packet)
	data := frame.Serialize()

	_, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("ошибка отправки Login: %w", err)
	}

	return nil
}
