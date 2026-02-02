// control/actions.go
package control

import (
	"encoding/binary"
	"log"
)

func SendMessage(conn interface{ Write([]byte) error }, message string) error {
	const TextPacketID = 0x0B
	msgLen := uint16(len(message))

	packet := []byte{TextPacketID, 0x01, 0x00, 0x03}
	packet = append(packet, "Bot"...)
	packet = append(packet, make([]byte, 2)...)
	binary.LittleEndian.PutUint16(packet[len(packet)-2:], msgLen)
	packet = append(packet, message...)

	err := conn.Write(packet)
	if err != nil {
		return err
	}
	log.Printf("💬 [->] %s", message)
	return nil
}

func Jump(conn interface{ Write([]byte) error }, x, y, z, yaw, pitch float32) {
	go func() {
		SendPosition(conn, x, y+0.2, z, yaw, pitch)
		time.Sleep(100 * time.Millisecond)
		SendPosition(conn, x, y, z, yaw, pitch)
	}()
}

func SendPosition(conn interface{ Write([]byte) error }, x, y, z, yaw, pitch float32) error {
	const MovePlayerPacketID = 0x0C
	packet := []byte{MovePlayerPacketID, 0x01}
	packet = appendFloat32(packet, x)
	packet = appendFloat32(packet, y)
	packet = appendFloat32(packet, z)
	packet = appendFloat32(packet, pitch)
	packet = appendFloat32(packet, yaw)
	packet = appendFloat32(packet, yaw)
	packet = append(packet, 0x00, 0x00)
	return conn.Write(packet)
}

func appendFloat32(buf []byte, f float32) []byte {
	bits := math.Float32bits(f)
	return append(buf, byte(bits), byte(bits>>8), byte(bits>>16), byte(bits>>24))
}
