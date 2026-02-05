package bedrock_rocket_bot

// NewMovePacket создаёт пакет движения
func NewMovePacket(x, y, z float64) []byte {
	buf := make([]byte, 0)
	WriteUint8(&buf, MovePlayerID)
	WriteUint64(&buf, 1) // Entity ID
	WriteFloat64(&buf, x)
	WriteFloat64(&buf, y)
	WriteFloat64(&buf, z)
	WriteFloat32(&buf, 0) // Pitch
	WriteFloat32(&buf, 0) // Yaw
	WriteFloat32(&buf, 0) // HeadYaw
	WriteUint8(&buf, 0)   // Mode
	WriteUint8(&buf, 0)   // OnGround
	return buf
}

// WriteFloat32 пишет float32
func WriteFloat32(buf *[]byte, v float32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, *(*uint32)(unsafe.Pointer(&v)))
	*buf = append(*buf, b...)
}

// WriteFloat64 пишет float64
func WriteFloat64(buf *[]byte, v float64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, *(*uint64)(unsafe.Pointer(&v)))
	*buf = append(*buf, b...)
}

