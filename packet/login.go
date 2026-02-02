// packet/login.go
package packet

import (
	"encoding/binary"
	"encoding/json"
)

func CreateLogin(username string, protocol uint32) []byte {
	var pkt []byte
	pkt = append(pkt, 0x01) // Login packet ID

	// Protocol Version
	pkt = append(pkt, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(pkt[1:5], protocol)

	// Chain Data (упрощённо)
	chainData := `{"chain":[]}`
	chainLen := uint32(len(chainData))
	pkt = append(pkt, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(pkt[5:9], chainLen)
	pkt = append(pkt, chainData...)

	// Skin Data (пусто)
	skinLen := uint32(0)
	pkt = append(pkt, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(pkt[9+len(chainData):9+len(chainData)+4], skinLen)

	// Client Data (JSON)
	clientData := map[string]interface{}{
		"ClientRandomId": 123456789,
		"DeviceOS":       7,
		"DeviceModel":    "PC",
		"GameVersion":    "1.20.10",
		"Username":       username,
		"LanguageCode":   "ru_RU",
	}
	clientJSON, _ := json.Marshal(clientData)
	clientLen := uint32(len(clientJSON))
	pkt = append(pkt, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(pkt[13+len(chainData):13+len(chainData)+4], clientLen)
	pkt = append(pkt, clientJSON...)

	return pkt
}
