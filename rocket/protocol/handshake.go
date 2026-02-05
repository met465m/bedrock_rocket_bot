package bedrock_rocket_bot

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Handshake проходит начальное рукопожатие с сервером (RakNet)
func Handshake(conn net.Conn) error {
	// OpenConnectionRequest1
	packet := []byte{0x05}
	packet = append(packet, make([]byte, 17)...) // MTU + GUID
	binary.BigEndian.PutUint64(packet[18:], 0)   // Client GUID

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(packet)
	if err != nil {
		return fmt.Errorf("ошибка отправки OpenConnectionRequest1: %w", err)
	}

	// Читаем ответ
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("ошибка чтения OpenConnectionReply1: %w", err)
	}

	if n < 1 || buf[0] != 0x06 {
		return fmt.Errorf("ожидался OpenConnectionReply1 (0x06), получен: %x", buf[0])
	}

	return nil
}
