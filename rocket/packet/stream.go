package bedrock_rocket_bot

import (
	"encoding/binary"
	"unsafe"
)

// WriteUint8 пишет byte
func WriteUint8(buf *[]byte, v byte) {
	*buf = append(*buf, v)
}

// WriteUint16 пишет uint16 (Big Endian)
func WriteUint16(buf *[]byte, v uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	*buf = append(*buf, b...)
}

// WriteUint32 пишет uint32
func WriteUint32(buf *[]byte, v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	*buf = append(*buf, b...)
}

// WriteUint64 пишет uint64
func WriteUint64(buf *[]byte, v uint64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	*buf = append(*buf, b...)
}

// WriteString пишет строку с длиной (uint16)
func WriteString(buf *[]byte, s string) {
	utf16len := uint16(len(s) * 2) // грубая оценка
	WriteUint16(buf, utf16len)
	*buf = append(*buf, s...)
}

// ReadUint8 читает byte
func ReadUint8(data *[]byte) byte {
	if len(*data) == 0 {
		return 0
	}
	v := (*data)[0]
	*data = (*data)[1:]
	return v
}

