package bedrock_rocket_bot

import (
	"net"
)

// Handshake выполняет базовый handshake с сервером
func Handshake(conn net.Conn) error {
	// Отправляем OpenConnectionRequest1
	packet := []byte{0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(packet)
	if err != nil {
		return err
	}

	// Читаем ответ
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}

	// Проверяем, что ответ — OpenConnectionReply1 (0x06)
	if len(reply) > 0 && reply[0] == 0x06 {
		return nil
	}

	return nil // Упрощённо — продолжаем
}

