package bedrock_rocket_bot

// Frame — фрейм RakNet
type Frame struct {
	Reliability byte
	Length      uint16
	Data        []byte
}

// NewFrame создаёт фрейм
func NewFrame(data []byte) *Frame {
	return &Frame{
		Reliability: 0x00, // Unreliable
		Length:      uint16(len(data)),
		Data:        data,
	}
}

// Serialize сериализует фрейм
func (f *Frame) Serialize() []byte {
	buf := make([]byte, 0, 3+len(f.Data))
	buf = append(buf, f.Reliability<<5) // Reliability в старших битах
	buf = append(buf, byte(f.Length), byte(f.Length>>8))
	buf = append(buf, f.Data...)
	return buf
}
