package bedrock_rocket_bot

import "bytes"

// Buffer — упрощённый буфер
type Buffer struct {
	Data []byte
}

// NewBuffer создаёт буфер
func NewBuffer() *Buffer {
	return &Buffer{Data: make([]byte, 0)}
}

// Write добавляет данные
func (b *Buffer) Write(data []byte) {
	b.Data = append(b.Data, data...)
}

