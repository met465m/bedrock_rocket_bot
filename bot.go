package github.com/met465m/bedrock_rocket_bot

import (
 "bytes"
 "context"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha256"
 "encoding/binary"
 "encoding/json" // For JWT parsing (simplified)
 "errors"
 "fmt"
 "io"
 "math"
 "math/big"
 "net"
 "strings"
 "sync"
 "time"
)

// Global constants for Bedrock protocol (simplified)
const (
 // RakNet Packet IDs
 RAKNET_UNCONNECTED_PING                  byte = 0x01
 RAKNET_UNCONNECTED_PONG                  byte = 0x1c
 RAKNET_OPEN_CONNECTION_REQUEST_1         byte = 0x05
 RAKNET_OPEN_CONNECTION_REPLY_1           byte = 0x06
 RAKNET_OPEN_CONNECTION_REQUEST_2         byte = 0x07
 RAKNET_OPEN_CONNECTION_REPLY_2           byte = 0x08
 RAKNET_CONNECTION_REQUEST_ACCEPTED       byte = 0x10 // Sometimes sent by server after RC2
 RAKNET_NEW_INCOMING_CONNECTION           byte = 0x13
 RAKNET_CONNECTED_PING                    byte = 0x00 // Within encapsulated data
 RAKNET_CONNECTED_PONG                    byte = 0x03 // Within encapsulated data
 RAKNET_FRAME_SET_PACKET_START            byte = 0x80 // All data packets (reliable/sequenced etc.) start here
 RAKNET_ACK_PACKET                        byte = 0xc0 // Acknowledge packet
 RAKNET_NACK_PACKET                       byte = 0xa0 // Not Acknowledge packet

 // Minecraft Bedrock Packet IDs (minimal for login)
 MCBE_LOGIN_PACKET                        byte = 0x01
 MCBE_PLAY_STATUS_PACKET                  byte = 0x02
 MCBE_SERVER_TO_CLIENT_HANDSHAKE_PACKET   byte = 0x03
 MCBE_CLIENT_TO_SERVER_HANDSHAKE_PACKET   byte = 0x04
 MCBE_TEXT_PACKET                         byte = 0x09 // Modern Bedrock Text Packet ID
 MCBE_START_GAME_PACKET                   byte = 0x0b // Start Game Packet ID (after successful login)

 // Play Statuses
 PLAY_STATUS_LOGIN_SUCCESS        uint32 = 0
 PLAY_STATUS_FAILED_CLIENT        uint32 = 1
 PLAY_STATUS_FAILED_SERVER        uint32 = 2
 PLAY_STATUS_PLAYER_SPAWN         uint32 = 3 // Sent after Start Game, indicates client can render
 PLAY_STATUS_LOGIN_NO_PERMISSIONS uint32 = 4

 DEFAULT_TIMEOUT = 10 * time.Second // Increased timeout for stability
 RAKNET_MAGIC = "\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"

 BEDROCK_PROTOCOL_VERSION = 622 // Example protocol for 1.20.70. You might need to adjust this!
)

// --- Structures required for minimal login ---

type Vector3 struct {
 X, Y, Z float64
}

type Item struct {
 ID    int32
 Count uint8
}

type Block struct {
 ID   uint16
 Meta byte
}

type Chunk struct {
 X, Z int32
 Data []byte
}

type Config struct {
 Username          string
 ServerAddr        string
 ServerPort        int
 Protocol          int // Bedrock Protocol Version
 ClientUUID        string
 EnableEncryption  bool // For future use, if we get to encryption
 // Keys for signing JWT (must be in config, or generated. Simplified for now)
 IdentityPrivateKey *ecdsa.PrivateKey
 IdentityPublicKey  *ecdsa.PublicKey
 Debug             bool
}

type BotState struct {
 CurrentPos      Vector3
 CurrentYaw      float32
 CurrentPitch    float32
 EntityID        int64
 RuntimeID       uint64
 SessionID       uint32
 Inventory       []Item // Unused for minimal login
 IsConnectedFlag bool
 Latency         time.Duration
 ServerGuid      uint64
 MtuSize         uint16
 ClientGuid      uint64
 // Encryption State
 SymmetricKey        []byte
 Cipher              cipher.Block
 Encrypter, Decrypter cipher.Stream
 EncryptionEnabled   bool

 // RakNet reliability state (minimal)
 lastSentSequenceNumber uint32
 lastReceivedSequenceNumber uint32
 pendingAcks []uint32
 ackTimer    *time.Timer
}

type OpenConnectionReply1 struct {
 ServerGuid uint64
 MtuSize    uint16
}

type RakConn struct {
 addr            *net.UDPAddr
 conn            *net.UDPConn
 readBuf         []byte
 mu              sync.Mutex
 timeout         time.Duration
 lastSeqNumSent  uint32
 lastSeqNumRecv  uint32
 ackQueue        []uint32 // Sequences to ACK
 ackTimer        *time.Timer
 frameQueue      chan []byte // Raw incoming RakNet frames
 packetSeqMu     sync.Mutex
 ackSendQueue    chan []byte
}

type Bot struct {
 conn             *RakConn
 packetHandlers   map[byte]func([]byte)
 eventListeners   map[string][]func(...interface{})
 state            BotState
 mu               sync.Mutex
 cancelCtx        context.Context
 cancelFunc       context.CancelFunc
 config           *Config
 sendQueue        chan []byte // Encapsulated Bedrock packets to send
 receiveQueue     chan []byte // Decapsulated Bedrock packets received
 connectionClosed chan struct{}
}

// NewBot creates and initializes a new Bot instance.
func NewBot(cfg *Config) *Bot {
 ctx, cancel := context.WithCancel(context.Background())
 if cfg.Protocol == 0 {
  cfg.Protocol = BEDROCK_PROTOCOL_VERSION
 }
 if cfg.ClientUUID == "" {
  cfg.ClientUUID = GenerateUUID()
 }
 // Generate dummy keys for JWT if not provided (for simple testing)
 if cfg.IdentityPrivateKey == nil {
  privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // P256 for demo
  cfg.IdentityPrivateKey = privateKey
  cfg.IdentityPublicKey = &privateKey.PublicKey
 }

 return &Bot{
  config:           cfg,
  packetHandlers:   make(map[byte]func([]byte)),
  eventListeners:   make(map[string][]func(...interface{})),
  state:            BotState{
   lastSentSequenceNumber: 0xFFFFFFFF, // Start from maximum to wrap around
   ackTimer:    time.NewTimer(time.Second), // Dummy timer
  },
  cancelCtx:        ctx,
  cancelFunc:       cancel,
  sendQueue:        make(chan []byte, 1024),
  receiveQueue:     make(chan []byte, 1024),
  connectionClosed: make(chan struct{}),
 }
}

// DialRakNet establishes a RakNet UDP connection.
func DialRakNet(addr string) (*RakConn, error) {
 udpAddr, err := net.ResolveUDPAddr("udp", addr)
 if err != nil {
  return nil, fmt.Errorf("bedrock_rocket_bot: failed to resolve UDP address: %w", err)
 }
 conn, err := net.DialUDP("udp", nil, udpAddr)
 if err != nil {
  return nil, fmt.Errorf("bedrock_rocket_bot: failed to dial UDP: %w", err)
 }

 rc := &RakConn{
  addr:            udpAddr,
  conn:            conn,
  // Using a large buffer, RakNet can handle large packets and fragmentation.
  // Maximum expected MTU for internet is 1500, but some games go higher.
  readBuf:         make([]byte, 8192),
  timeout:         DEFAULT_TIMEOUT,
  lastSeqNumSent:  0, // RakNet sequence numbers start from 0
  lastSeqNumRecv:  0,
  ackQueue:        make([]uint32, 0, 10),
  ackTimer:        time.NewTimer(100 * time.Millisecond), // ACK every 100ms
  frameQueue:      make(chan []byte, 1024),
  ackSendQueue:    make(chan []byte, 1024),
 }
 rc.ackTimer.Stop() // Stop timer until we have ACKs to send
 return rc, nil
}

// SendFrame encapsulates Minecraft packet(s) within a RakNet data frame and sends it.
// This is a *highly simplified* RakNet reliable sequenced packet sender.
// A real RakNet implementation would be infinitely more complex (fragmentation, retransmission, etc.)
func (rc *RakConn) SendFrame(data []byte, reliability byte) error {
 rc.packetSeqMu.Lock()
 seq := rc.lastSeqNumSent
 rc.lastSeqNumSent++
 rc.packetSeqMu.Unlock()

 var buf bytes.Buffer
 // RakNet packet ID for sequenced and reliable packets
 // 0x80 to 0x8f are data packet IDs
 // 0x84 - Reliable and Sequenced, 0x85 - Reliable Ordered (most common for MCBE)
 frameHeaderID := RAKNET_FRAME_SET_PACKET_START | reliability // e.g., 0x85 for reliable ordered

 WriteUint8(&buf, frameHeaderID)
 WriteUint24(&buf, seq) // RakNet Sequence Number

 // Encapsulated frame(s)
 // Forsimplicity, one encapsulated frame per RakNet packet
 // RakNet Encapsulated Header:
 // Flag byte (reliability, has_split, ...)
 // If has_split: split_count (uint32), split_id (uint16), split_index (uint32)
 // If reliable: reliability_index (uint32)
 // Length (uint16, in bits)
 // Data
 
 // Flags for ReliableOrdered (0x85) with length
 encapFlags := byte(0b01000000) // 0x40 - Reliable, 0x80 - Has Message Index (for ordered)
 encapFlags |= reliability << 5 // Simplified, usually more complex
 
 var encapBuf bytes.Buffer
 WriteUint8(&encapBuf, encapFlags)
 
 // Reliability index (message index) for ordered packets
 WriteUint24(&encapBuf, seq) // Using RakNet sequence as message index for simplicity

 // Length in bits (not bytes)
 WriteUint16(&encapBuf, uint16(len(data)*8))
 encapBuf.Write(data) // The actual Minecraft packet payload

 // Write encapsulated data into the main buffer
 buf.Write(encapBuf.Bytes())

 _, err := rc.conn.Write(buf.Bytes())
 if err != nil {
  return fmt.Errorf("bedrock_rocket_bot: error sending RakNet frame: %w", err)
 }
 return nil
}

// ReadFrame reads a raw UDP packet and attempts to process as a RakNet frame.
// This is also a *highly simplified* RakNet receiver.
// It will parse basic RakNet headers, extract sequence numbers, and put
// encapsulated data into the frameQueue. It will also queue ACKs.
func (rc *RakConn) ReadFrame() ([]byte, error) {
 select {
 case frame := <-rc.frameQueue:
  return frame, nil
 case <-time.After(rc.timeout):
  return nil, errors.New("bedrock_rocket_bot: RakNet frame read timeout (from queue)")
 }
}

// rakNetPacketReaderLoop continuously reads from UDP and processes RakNet frames.
func (rc *RakConn) rakNetPacketReaderLoop(cancelCtx context.Context) {
 defer fmt.Println("bedrock_rocket_bot: RakNet packet reader loop finished.")
 for {
  select {
  case <-cancelCtx.Done():
   return
  default:
   rc.conn.SetReadDeadline(time.Now().Add(rc.timeout))
   n, _, err := rc.conn.ReadFromUDP(rc.readBuf)
   if err != nil {
    if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
     continue
    }
    fmt.Printf("bedrock_rocket_bot: RakNet UDP read error: %v\n", err)
    // FIX: This error should lead to a higher-level reconnect attempt
    return
   }
   if n == 0 {
    continue
   }

   reader := bytes.NewReader(rc.readBuf[:n])
   packetID, _ := ReadUint8(reader)

   if packetID == RAKNET_UNCONNECTED_PONG {
    // We don't care about pongs here, but a real client would parse it to get GUID/MOTD.
    continue
   } else if packetID == RAKNET_OPEN_CONNECTION_REPLY_1 || packetID == RAKNET_OPEN_CONNECTION_REPLY_2 ||
    packetID == RAKNET_NEW_INCOMING_CONNECTION || packetID == RAKNET_CONNECTION_REQUEST_ACCEPTED {
    // These are raw RakNet discovery/handshake packets that need to be processed directly
    // by the main handshake logic, not decapsulated Minecraft packets.
    select {
    case rc.frameQueue <- rc.readBuf[:n]:
    case <-cancelCtx.Done():
     return
    }
    continue
   } else if (packetID >= RAKNET_FRAME_SET_PACKET_START && packetID <= 0x8f) || // Data packets
     packetID == RAKNET_ACK_PACKET || packetID == RAKNET_NACK_PACKET { // ACK/NACK
    // Handle data packets or ACK/NACKs
    rc.processRakNetDataPacket(packetID, reader, cancelCtx)
   } else {
    // Unknown RakNet packet or other low-level type, put raw into queue
    select {
    case rc.frameQueue <- rc.readBuf[:n]:
    case <-cancelCtx.Done():
     return
    }
   }
  }
 }
}

// processRakNetDataPacket processes an incoming RakNet data packet.
// This is the core of simplified RakNet data handling.
func (rc *RakConn) processRakNetDataPacket(packetID byte, reader *bytes.Reader, cancelCtx context.Context) {
 if packetID == RAKNET_ACK_PACKET || packetID == RAKNET_NACK_PACKET {
  // A proper RakNet impl would parse these and update retransmission queues.
  // For minimal login, we just ignore incoming ACKs/NACKs.
  return
 }

 // For data packets (0x80-0x8f):
 // Sequence number (3 bytes)
 seq, _ := ReadUint24(reader)
 rc.packetSeqMu.Lock()
 rc.lastSeqNumRecv = seq // Keep track of latest sequence
 rc.packetSeqMu.Unlock()

 // Queue this sequence number for ACK
 rc.mu.Lock()
 rc.ackQueue = append(rc.ackQueue, seq)
 if rc.ackTimer.Stop() { // Restart timer if it was running
  rc.ackTimer.Reset(100 * time.Millisecond)
 } else { // If it wasn't running, start it
  rc.ackTimer = time.AfterFunc(100 * time.Millisecond, func() { rc.sendAcknowledgedPackets(cancelCtx) })
 }
 rc.mu.Unlock()

 // Decapsulate inner frames (there could be multiple in one RakNet packet)
 for reader.Len() > 0 {
  // Encapsulated header is typically:
  // Flag byte (reliability, has_split, ...)
  // If reliable: message_index (3 bytes)
  // If has_split: split_count (4 bytes), split_id (2 bytes), split_index (4 bytes)
  // Length (2 bytes, in bits)
  // Data
  
  flags, err := ReadUint8(reader)
  if err != nil { break }

  hasMsgIndex := (flags & 0b10000000) != 0 // Highest bit indicates message index
  // Has Split packets (fragmentation) - we'll ignore for now
  // isReliable := (flags & 0b01000000) != 0 // Second highest bit

  if hasMsgIndex {
   _, _ = ReadUint24(reader) // Message Index (used for ordered/reliable ordered packets)
  }
  
  // If has split flag, read split info. We don't implement fragmentation for minimal.
  // if (flags & 0x08) != 0 { ... read split info ... }

  lengthBits, err := ReadUint16(reader)
  if err != nil { break }
  lengthBytes := lengthBits / 8

  if int(lengthBytes) > reader.Len() {
   fmt.Printf("bedrock_rocket_bot: warning: encapsulated frame length (%d) exceeds remaining buffer (%d). Corrupt packet?\n", lengthBytes, reader.Len())
   break
  }
  
  payload := make([]byte, lengthBytes)
  _, err = io.ReadFull(reader, payload)
  if err != nil { break }

  select {
  case rc.frameQueue <- payload:
  case <-cancelCtx.Done():
   return
  }
 }
}

// sendAcknowledgedPackets sends an ACK packet with all queued sequence numbers.
func (rc *RakConn) sendAcknowledgedPackets(cancelCtx context.Context) {
 rc.mu.Lock()
 if len(rc.ackQueue) == 0 {
  rc.ackTimer.Stop()
  rc.mu.Unlock()
  return
 }

 sequencesToSend := make([]uint32, len(rc.ackQueue))
 copy(sequencesToSend, rc.ackQueue)
 rc.ackQueue = rc.ackQueue[:0] // Clear queue

 rc.mu.Unlock()

 var buf bytes.Buffer
 WriteUint8(&buf, RAKNET_ACK_PACKET)
 
 // Write Record Count (always 1 for a block of ACKs here, simplified)
 WriteUint16(&buf, 1)

 // Write a record: is_range (1 byte), start_seq (3 bytes), end_seq (3 bytes)
 // For minimal implementation, we assume a single continuous range for simplicity
 if len(sequencesToSend) > 0 {
  // Find min and max for a range
  minSeq := sequencesToSend[0]
  maxSeq := sequencesToSend[0]
  for _, s := range sequencesToSend {
   if s < minSeq { minSeq = s }
   if s > maxSeq { maxSeq = s }
  }

  WriteUint8(&buf, 0x01) // Is_range = true
  WriteUint24(&buf, minSeq)
  WriteUint24(&buf, maxSeq)
 } else {
  return // Should not happen if check above works
 }
 
 select {
 case rc.ackSendQueue <- buf.Bytes():
 case <-cancelCtx.Done():
  return
 }
 
 // Restart the timer only if there are still pending ACKs in the main queue,
 // or if we expect more to come in. For now, it's restarted once ACKs are sent.
 rc.mu.Lock()
 if rc.ackTimer.Stop() {
  rc.ackTimer.Reset(100 * time.Millisecond)
 }
 rc.mu.Unlock()
}

// rakNetAckSenderLoop sends ACK/NACK packets from the queue.
func (rc *RakConn) rakNetAckSenderLoop(cancelCtx context.Context) {
 defer fmt.Println("bedrock_rocket_bot: RakNet ACK sender loop finished.")
 for {
  select {
  case <-cancelCtx.Done():
   return
  case ackPacket := <-rc.ackSendQueue:
   _, err := rc.conn.Write(ackPacket)
   if err != nil {
    fmt.Printf("bedrock_rocket_bot: error sending ACK packet: %v\n", err)
   }
  case <-rc.ackTimer.C: // Timer for periodic ACKs (if no data to trigger immediate ACK)
   rc.sendAcknowledgedPackets(cancelCtx)
  }
 }
}


// CloseConnection closes the RakNet UDP connection.
func (rc *RakConn) CloseConnection() error {
 return rc.conn.Close()
}

// SetTimeout sets the read/write timeout for the RakNet connection.
func (rc *RakConn) SetTimeout(duration time.Duration) {
 rc.timeout = duration
}

// SendOpenConnectionRequest1 sends the first RakNet connection request.
func (b *Bot) SendOpenConnectionRequest1() error {
 var buf bytes.Buffer
 WriteUint8(&buf, RAKNET_OPEN_CONNECTION_REQUEST_1)
 WriteRakNetMagic(&buf)
 WriteUint8(&buf, byte(b.config.Protocol)) // Protocol version
 WriteBytes(&buf, make([]byte, 20))         // Padding to reach min 40 bytes

 return b.conn.SendFrame(buf.Bytes(), 0x00) // Unreliable connection
}

// ReceiveOpenConnectionReply1 receives and parses the first RakNet connection reply.
func (b *Bot) ReceiveOpenConnectionReply1() (*OpenConnectionReply1, error) {
 frame, err := b.conn.ReadFrame()
 if err != nil {
  return nil, fmt.Errorf("bedrock_rocket_bot: failed to receive OpenConnectionReply1: %w", err)
 }
 if len(frame) < 32 || frame[0] != RAKNET_OPEN_CONNECTION_REPLY_1 { // Min length check for reply
  return nil, errors.New("bedrock_rocket_bot: invalid or short OpenConnectionReply1 packet")
 }

 reader := bytes.NewReader(frame[1:]) // Skip packet ID
 ReadRakNetMagic(reader)              // Consume magic
 serverGuid, _ := ReadUint64(reader)
 mtuSize, _ := ReadUint16(reader)
 // Security flags, usually 0 for Bedrock
 
 b.mu.Lock()
 b.state.ServerGuid = serverGuid
 b.state.MtuSize = mtuSize
 b.mu.Unlock()

 return &OpenConnectionReply1{
  ServerGuid: serverGuid,
  MtuSize:    mtuSize,
 }, nil
}

// SendOpenConnectionRequest2 sends the second RakNet connection request.
func (b *Bot) SendOpenConnectionRequest2(serverGuid uint64, mtu uint16) error {
 b.mu.Lock()
 b.state.ClientGuid = GenerateUUIDUint64() // Generate a unique client GUID
 clientGuid := b.state.ClientGuid
 b.mu.Unlock()

 var buf bytes.Buffer
 WriteUint8(&buf, RAKNET_OPEN_CONNECTION_REQUEST_2)
 WriteRakNetMagic(&buf)
 WriteUint64(&buf, serverGuid)
 WriteUint16(&buf, mtu)
 WriteUint64(&buf, clientGuid)
 
 return b.conn.SendFrame(buf.Bytes(), 0x00) // Unreliable connection
}

// ReceiveOpenConnectionReply2 waits for OpenConnectionReply2.
// This is critical for getting the Server GUID and confirming successful RakNet setup.
func (b *Bot) ReceiveOpenConnectionReply2() error {
 frame, err := b.conn.ReadFrame()
 if err != nil {
  return fmt.Errorf("bedrock_rocket_bot: failed to receive OpenConnectionReply2: %w", err)
 }
 if len(frame) < 25 || (frame[0] != RAKNET_OPEN_CONNECTION_REPLY_2 && frame[0] != RAKNET_NEW_INCOMING_CONNECTION && frame[0] != RAKNET_CONNECTION_REQUEST_ACCEPTED) {
  return errors.New("bedrock_rocket_bot: invalid or unexpected packet for OpenConnectionReply2")
 }
 
 // A real implementation would parse the packet type to get details.
 // For minimal, we just confirm *a* reply came.
 return nil
}

// ValidateHandshake performs additional validation on the handshake reply.
func (b *Bot) ValidateHandshake(reply *OpenConnectionReply1) bool {
 return reply != nil && reply.ServerGuid != 0 && reply.MtuSize > 0
}

// BuildLoginPacket constructs the Minecraft Bedrock login packet, including JWT signing.
// This is still highly simplified but attempts to mimic the structure.
func (b *Bot) BuildLoginPacket(username string, protocol int, clientUUID string, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
 // 1. Create Identity Token (JWT)
 // Header: {"alg":"ES384","x5u":"<public_key_base64>"}
 // Payload: {"exp":<timestamp>,"nbf":<timestamp>,"iss":"<client_uuid>","aud":"client.realms.minecraft.net","iat":<timestamp>,"sub":"<client_uuid>","certChain":[]}
 // The actually-used curve is P384, but we use P256 for easier generation if only dummy.

 // A *real* Bedrock client would authenticate with Xbox Live to get an XBL token,
 // then put that token into the JWT chain as an "extra" certificate.
 // For minimal login, we'll construct a self-signed JWT without actual XBL auth.

 // Dummy XUID and DisplayName (these *should* come from XBL auth)
 dummyXUID := "2535496695280961" // Example XUID
 dummyDisplayName := username

 // JWT Payload
 claims := map[string]interface{}{
  "exp": time.Now().Add(24 * time.Hour).Unix(),
  "nbf": time.Now().Unix(),
  "iss": clientUUID,
"aud": "client.realms.minecraft.net",
  "iat": time.Now().Unix(),
  "sub": clientUUID,
  "titleId": "896928775", // Minecraft Bedrock TitleID
  "random_number": math.Floor(rand.Float64() * 1000000000), // Some random number
  "identity": map[string]string{
   "XBOX_USER_ID": dummyXUID,
  },
  "properties": map[string]interface{} {
   "DeveloperConsole": false,
   "DeviceModel": "PC",
  },
 }
 payloadBytes, _ := json.Marshal(claims)

 // JWT Header (with public key)
 pubKeySecp256r1 := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
 pubKeyBase64 := Base64Encode(pubKeySecp256r1)
 header := map[string]string{
  "alg": "ES384", // Use ES384 algorithm for signing
  "x5u": pubKeyBase64,
 }
 headerBytes, _ := json.Marshal(header)

 // Build raw JWT
 jwtRaw := Base64Encode(headerBytes) + "." + Base64Encode(payloadBytes)

 // Sign the JWT
 hash := sha256.Sum256([]byte(jwtRaw)) // Bedrock uses SHA256 for P256/P384 for JWT, NOT just for data.
 r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
 if err != nil {
  return nil, fmt.Errorf("bedrock_rocket_bot: failed to sign JWT: %w", err)
 }
 
 // Convert r and s to fixed-size byte slices (P256 uses 32 bytes)
 rBytes := r.FillBytes(make([]byte, 32)) 
 sBytes := s.FillBytes(make([]byte, 32))
 
 signature := Base64Encode(append(rBytes, sBytes...))
 fullJWT := jwtRaw + "." + signature

 // 2. Build Login Payload (JSON structure for ClientData and ChainData)
 chainData := map[string]interface{}{
  "chain": []string{fullJWT},
 }
 chainDataBytes, _ := json.Marshal(chainData)
 chainDataStr := string(chainDataBytes)

 // ClientData part (more complex, contains skin info, device info etc.)
 clientData := map[string]interface{}{
  "DeviceModel": "PC", // or "Apple iPad", "Google Pixel", etc.
  "ClientRandomId": time.Now().UnixNano(),
  "CurrentInputMode": 1, // 1 for mouse/keyboard
  "DefaultInputMode": 1,
  "DeviceOS": 7, // 7 for Windows
  "GameVersion": fmt.Sprintf("%d.0.0", protocol/10000), // Simplified to "1.XX.0.0"
  "GuiScale": 0,
  "LanguageCode": "en_US",
  // ... many more client settings
  "PlayerId": "", // Empty for login
  "ServerAddress": fmt.Sprintf("%s:%d", b.config.ServerAddr, b.config.ServerPort),
  "SkinData": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", // Minimal 1x1 base64 transparent PNG
  "SkinId": "Custom",
  "SkinGeometryData": "{}",
  "ThirdPartyName": dummyDisplayName,
  "ThirdPartyNameOnly": false,
  "UIProfile": 0,
  "XboxUserId": dummyXUID,
  "CapeData": "",
  "PersonaPieces": []interface{}{},
  "PieceTintColors": []interface{}{},
  "ArmSize": "",
  "PlayFabId": GenerateUUID(),
  "PlatformOnlineId": "",
  "SelfSignedId": clientUUID,
  "LiveId": dummyXUID,
 }
 clientDataBytes, _ := json.Marshal(clientData)
 clientDataStr := string(clientDataBytes)

 // 3. Assemble the final Minecraft Login packet (0x01)
 var finalLoginBuf bytes.Buffer
 WriteUint32LE(&finalLoginBuf, uint32(protocol)) // Protocol version

 WriteString(&finalLoginBuf, chainDataStr)
 WriteString(&finalLoginBuf, clientDataStr)

 payload := finalLoginBuf.Bytes()

 var packetBuf bytes.Buffer
 WriteUint8(&packetBuf, MCBE_LOGIN_PACKET)
 WriteUint32LE(&packetBuf, uint32(len(payload))) // Length prefix for the whole payload
 packetBuf.Write(payload)

 return packetBuf.Bytes(), nil
}

// SendLogin sends the crafted login packet to the server.
func (b *Bot) SendLogin() error {
 b.mu.Lock()
 username := b.config.Username
 protocol := b.config.Protocol
 clientUUID := b.config.ClientUUID
 privateKey := b.config.IdentityPrivateKey
 publicKey := b.config.IdentityPublicKey
 b.mu.Unlock()

 loginPacket, err := b.BuildLoginPacket(username, protocol, clientUUID, privateKey, publicKey)
 if err != nil {
  return fmt.Errorf("bedrock_rocket_bot: error building login packet: %w", err)
 }
 
 // Login packet is ReliableOrdered (0x85)
 return b.sendQueuePacket(loginPacket, 0x05)
}

// ParsePlayStatus parses the Play Status packet 
(0x02).
func (b *Bot) ParsePlayStatus(packet []byte) (uint32, error) {
 if len(packet) < 5 || packet[0] != MCBE_PLAY_STATUS_PACKET {
  return 0, errors.New("bedrock_rocket_bot: invalid or short PlayStatus packet")
 }
 reader := bytes.NewReader(packet[1:])
 status, _ := ReadUint32LE(reader) // Assume Little Endian
 return status, nil
}

// WaitForLoginSuccess waits for a Play Status packet indicating successful login.
// It also handles ServerToClientHandshake for encryption setup.
func (b *Bot) WaitForLoginSuccess() error {
 for {
  select {
  case <-b.cancelCtx.Done():
   return errors.New("bedrock_rocket_bot: login wait canceled")
  default:
   frame, err := b.conn.ReadFrame()
   if err != nil {
    if strings.Contains(err.Error(), "timeout") {
     continue
    }
    return fmt.Errorf("bedrock_rocket_bot: error reading frame during login wait: %w", err)
   }
   
   // Decrypt if encryption is enabled (and keys are set)
   var packetData []byte = frame
   if b.state.EncryptionEnabled && b.state.Decrypter != nil {
    decrypted, decErr := b.DecryptPayload(frame)
    if decErr == nil {
     packetData = decrypted
    } else {
     fmt.Printf("bedrock_rocket_bot: warning: failed to decrypt frame during login: %v\n", decErr)
     // If decryption fails, maybe it's not encrypted yet or keys are wrong.
     // Try to process raw.
    }
   }

   id, payload, err := b.DeserializePacket(packetData)
   if err != nil {
    //fmt.Printf("bedrock_rocket_bot: warning: failed to deserialize packet during login: %v\n", err) // Too chatty
    continue
   }

   if id == MCBE_PLAY_STATUS_PACKET {
    status, err := b.ParsePlayStatus(packetData) // Pass original frame with ID for PlayStatus parsing
    if err != nil {
     fmt.Printf("bedrock_rocket_bot: warning: failed to parse PlayStatus: %v\n", err)
     continue
    }
    if status == PLAY_STATUS_LOGIN_SUCCESS || status == PLAY_STATUS_PLAYER_SPAWN {
     return nil // Success!
    }
    if b.config.Debug {
     fmt.Printf("bedrock_rocket_bot: received PlayStatus: %d\n", status)
    }
   } else if id == MCBE_SERVER_TO_CLIENT_HANDSHAKE_PACKET {
    // This packet contains the public key for ECDH key exchange
    // to derive the symmetric encryption key.
    if b.config.Debug {
     fmt.Println("bedrock_rocket_bot: received ServerToClientHandshake. Setting up encryption...")
    }
    if err := b.handleServerToClientHandshake(payload); err != nil {
     return fmt.Errorf("bedrock_rocket_bot: failed to handle S2C handshake: %w", err)
    }
    // Reply with ClientToServerHandshake
    if err := b.sendClientToServerHandshake(); err != nil {
     return fmt.Errorf("bedrock_rocket_bot: failed to send C2S handshake: %w", err)
    }
   }
   b.DispatchPacket(id, payload) // Dispatch other packets
  }
 }
}

// handleServerToClientHandshake processes the server's public key for encryption.
func (b *Bot) handleServerToClientHandshake(payload []byte) error {
 reader := bytes.NewReader(payload)
 jwtStr, err := ReadString(reader) // The JWT contains the public key
 if err != nil {
  return fmt.Errorf("failed to read JWT from S2C Handshake: %w", err)
 }

 // Parse JWT to extract server's public key
 parts := strings.Split(jwtStr, ".")
 if len(parts) != 3 {
  return errors.New("invalid JWT format in S2C Handshake")
 }
 headerBytes, err := Base64Decode(parts[0])
 if err != nil { return fmt.Errorf("failed to decode JWT header: %w", err) }
 
 var header struct { X5U string `json:"x5u"` }
 if err := json.Unmarshal(headerBytes, &header); err != nil {
  return fmt.Errorf("failed to unmarshal JWT header: %w", err)
 }

 serverPubKeyBytes, err := Base64Decode(header.X5U)
 if err != nil { return fmt.Errorf("failed to decode server public key: %w", err) }

 curve := elliptic.P384() // Bedrock typically uses P384 for encryption keys
 x, y := elliptic.Unmarshal(curve, serverPubKeyBytes)
 if x == nil { return errors.New("failed to unmarshal server public key") }
 serverPublicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

 // Perform ECDH key exchange to derive symmetric key
 privateKey, err := ecdsa.GenerateKey(curve, rand.Reader) // Generate ephemeral key
 if err != nil { return fmt.Errorf("failed to generate ephemeral ECDH key: %w", err) }

 secretX, _ := curve.ScalarMult(serverPublicKey.X, serverPublicKey.Y, privateKey.D.Bytes())
 sharedSecret := sha256.Sum256(secretX.Bytes()) // Hash the shared secret to create symmetric key

 b.mu.Lock()
 b.state.SymmetricKey = sharedSecret[:]
 b.state.Cipher, err = aes.NewCipher(b.state.SymmetricKey)
 if err != nil { b.mu.Unlock(); return fmt.Errorf("failed to create AES cipher: %w", err) }
 
 // IV is derived from shared secret (usually first 16 bytes of shared secret hash)
 iv := make([]byte, aes.BlockSize) 
 copy(iv, sharedSecret[:aes.BlockSize])

 b.state.Encrypter = cipher.NewCFB8(b.state.Cipher, iv, false) // CFB8 encrypter
 b.state.Decrypter = cipher.NewCFB8(b.state.Cipher, iv, true)  // CFB8 decrypter
 b.state.EncryptionEnabled = true
 b.mu.Unlock()

 if b.config.Debug {
  fmt.Println("bedrock_rocket_bot: encryption setup complete.")
 }
 return nil
}

// sendClientToServerHandshake sends the client's public key (ephemeral) to the server.
func (b *Bot) sendClientToServerHandshake() error {
 // This packet typically just sends our ephemeral public key back to the server.
 var buf bytes.Buffer
 // Create another dummy JWT containing our ephemeral public key
 // This is a simplification; usually, the client would send its own ephemeral public key directly
 // or as part of a single JWT, not in a chain like this.
 ephemeralPubKeyBytes := elliptic.Marshal(b.config.IdentityPrivateKey.Curve, b.config.IdentityPrivateKey.X, b.config.IdentityPrivateKey.Y)
 ephemeralPubKeyBase64 := Base64Encode(ephemeralPubKeyBytes)

 header := map[string]string{"alg": "ES384", "x5u": ephemeralPubKeyBase64}
 headerBytes, _ := json.Marshal(header)
 
 payload := map[string]interface{}{
  "exp": time.Now().Add(1 * time.Hour).Unix(),
  "nbf": time.Now().Unix(),
  "iss": b.config.ClientUUID,
  "iat": time.Now().Unix(),
  "sub": b.config.ClientUUID,
 }
 payloadBytes, _ := json.Marshal(payload)

 jwtRaw := Base64Encode(headerBytes) + "." + Base64Encode(payloadBytes)
 
 hash := sha256.Sum256([]byte(jwtRaw))
 r, s, err := ecdsa.Sign(rand.Reader, b.config.IdentityPrivateKey, hash[:])
 if err != nil { return fmt.Errorf("failed to sign ephemeral key JWT: %w", err) }

 rBytes := r.FillBytes(make([]byte, 32))
 sBytes := s.FillBytes(make([]byte, 32))
 signature := Base64Encode(append(rBytes, sBytes...))
 fullJWT := jwtRaw + "." + signature

 WriteString(&buf, fullJWT) // Send the JWT (or just the public key)

 packet := b.SerializePacket(MCBE_CLIENT_TO_SERVER_HANDSHAKE_PACKET, buf.Bytes())
 return b.sendQueuePacket(packet, 0x05) // ReliableOrdered
}


// SerializePacket combines packet ID and payload into a single byte slice.
func (b *Bot) SerializePacket(id byte, payload []byte) []byte {
 var buf bytes.Buffer
 WriteUint8(&buf, id)
 buf.Write(payload)
 return buf.Bytes()
}

// DeserializePacket extracts packet ID and payload from a byte slice.
func (b *Bot) DeserializePacket(data []byte) (id byte, payload []byte, err error) {
 if len(data) == 0 {
  return 0, nil, errors.New("bedrock_rocket_bot: empty data to deserialize")
 }
 id = data[0]
 payload = data[1:]
 return id, payload, nil
}

// RegisterPacketHandler registers a function to handle incoming packets of a specific ID.
func (b *Bot) RegisterPacketHandler(id byte, handler func([]byte)) {
 b.packetHandlers[id] = handler
}

// DispatchPacket calls the appropriate handler for a given packet ID.
func (b *Bot) DispatchPacket(id byte, data []byte) {
 if handler, ok := b.packetHandlers[id]; ok {
  handler(data)
 } else if b.config.Debug {
  // fmt.Printf("bedrock_rocket_bot: info: unhandled packet ID: 0x%02x, payload length: %d\n", id, len(data)) // Too chatty
 }
}

// GetPacketName provides a human-readable name for a given packet ID.
func (b *Bot) GetPacketName(id byte) string {
 switch id {
 case MCBE_LOGIN_PACKET: return "Login"
 case MCBE_PLAY_STATUS_PACKET: return "Play Status"
 case MCBE_SERVER_TO_CLIENT_HANDSHAKE_PACKET: return "Server To Client Handshake"
 case MCBE_CLIENT_TO_SERVER_HANDSHAKE_PACKET: return "Client To Server Handshake"
 case MCBE_TEXT_PACKET: return "Text"
 case MCBE_START_GAME_PACKET: return "Start Game"
 default: return fmt.Sprintf("Unknown(0x%02x)", id)
 }
}

// Minimal actions (we only need Chat for now, others are stubs)
func (b *Bot) Move(direction string, blocks float64) error { return nil }
func (b *Bot) Jump() error { return nil }
func (b *Bot) Turn(direction string, degrees float32) error { return nil }
func (b *Bot) MoveTo(x, y, z float64) error { return nil }
func (b *Bot) TurnLook(yaw, pitch float32) error { return nil } // Renamed to avoid clash with Turn
func (b *Bot) UseItem(slot int) error { return nil }
func (b *Bot) SwapHand() error { return nil }
func (b *Bot) Attack(targetID int) error { return nil }
func (b *Bot) InteractBlock(pos Vector3, face int) error { return nil }


// SendChatMessage sends a chat message.
func (b *Bot) SendChatMessage(text string) error {
 var buf bytes.Buffer
 WriteUint8(&buf, 0x01)            // Text Type: Chat (byte 0x01)
 WriteUint8(&buf, 0)               // Needs Translation: false
 WriteString(&buf, b.config.Username) // Source name (bot's username)
 WriteString(&buf, text)           // Message
 WriteString(&buf, "")             // Message Parameters
 WriteUint64LE(&buf, 0)            // XUID (placeholder)
 WriteString(&buf, "")             // Platform Chat ID (placeholder)
 // Additional fields like Tick and UnkownInt

 packet := b.SerializePacket(MCBE_TEXT_PACKET, buf.Bytes())
 return b.sendQueuePacket(packet, 0x05) // ReliableOrdered
}

// OnJoin event handler.
func (b *Bot) OnJoin() {
 fmt.Println("INFO: Bot joined the server!")
 b.dispatchEvent("OnJoin")
}

// OnDisconnect event handler.
func (b *Bot) OnDisconnect() {
 fmt.Println("INFO: Bot disconnected from the server.")
 b.dispatchEvent("OnDisconnect")
}

// OnChatMessage event handler.
func (b *Bot) OnChatMessage(sender, text string) {
 fmt.Printf("[CHAT] <%s> %s\n", sender, text)
 b.dispatchEvent("OnChatMessage", sender, text)
}

// Other On... methods are stubs
func (b *Bot) OnPlayerMove(playerID int, pos Vector3, yaw, pitch float32) {}
func (b *Bot) OnEntitySpawn(entityID int, pos Vector3) {}
func (b *Bot) OnDeath() {}
func (b *Bot) OnInventoryUpdate(items []Item) {}
func (b *Bot) OnChunkData(chunkX, chunkZ int32, data []byte) {}


// --- Byte Reading/Writing Utilities (Little Endian for Bedrock) ---

func WriteUint8(buf *bytes.Buffer, v uint8) { buf.WriteByte(v) }
func WriteUint16(buf *bytes.Buffer, v uint16) { binary.Write(buf, binary.LittleEndian, v) }
func WriteUint24(buf *bytes.Buffer, v uint32) {
 WriteUint8(buf, byte(v))
 WriteUint8(buf, byte(v>>8))
 WriteUint8(buf, byte(v>>16))
}
func WriteUint32LE(buf *bytes.Buffer, v uint32) { binary.Write(buf, binary.LittleEndian, v) }
func WriteUint64LE(buf *bytes.Buffer, v uint64) { binary.Write(buf, binary.LittleEndian, v) }
func WriteInt32LE(buf *bytes.Buffer, v int32) { binary.Write(buf, binary.LittleEndian, v) }
func WriteFloat32LE(buf *bytes.Buffer, v float32) { binary.Write(buf, binary.LittleEndian, math.Float32bits(v)) }
func WriteFloat64(buf *bytes.Buffer, v float64) { binary.Write(buf, binary.LittleEndian, math.Float64bits(v)) }
func WriteString(buf *bytes.Buffer, s string) {
 bytes := []byte(s)
 WriteUint32LE(buf, uint32(len(bytes))) // Length prefix (Little Endian uint32 for MCBE)
 buf.Write(bytes)
}
func WriteBytes(buf *bytes.Buffer, b []byte) { buf.Write(b) }
func WriteRakNetMagic(buf *bytes.Buffer) { buf.WriteString(RAKNET_MAGIC) } // Write string directly


func ReadUint8(r *bytes.Reader) (uint8, error) { b, err := r.ReadByte(); return b, err }
func ReadUint16(r *bytes.Reader) (uint16, error) { var v uint16; err := binary.Read(r, binary.LittleEndian, &v); return v, err }
func ReadUint24(r *bytes.Reader) (uint32, error) {
 b1, err := r.ReadByte(); if err != nil { return 0, err }
 b2, err := r.ReadByte(); if err != nil { return 0, err }
 b3, err := r.ReadByte(); if err != nil { return 0, err }
 return uint32(b1) | (uint32(b2) << 8) | (uint32(b3) << 16), nil
}
func ReadUint32LE(r *bytes.Reader) (uint32, error) { var v uint32; err := binary.Read(r, binary.LittleEndian, &v); return v, err }
func ReadUint64(r *bytes.Reader) (uint64, error) { var v uint64; err := binary.Read(r, binary.LittleEndian, &v); return v, err }
func ReadFloat32LE(r *bytes.Reader) (float32, error) { var v uint32; err := binary.Read(r, binary.LittleEndian, &v); return math.Float32frombits(v), err }
func ReadString(r *bytes.Reader) (string, error) {
 length, err := ReadUint32LE(r); if err != nil { return "", err }
 strBytes := make([]byte, length); _, err = r.Read(strBytes); if err != nil { return "", err }
 return string(strBytes), nil
}
func ReadRakNetMagic(r *bytes.Reader) error {
 magic := make([]byte, len(RAKNET_MAGIC)); _, err := r.Read(magic); if err != nil { return err }
 if string(magic) != RAKNET_MAGIC { return errors.New("bedrock_rocket_bot: invalid RakNet magic bytes") }
 return nil
}

// --- Math and Utility functions ---

func Vector3Distance(a, b Vector3) float64 { return 0 }
func NormalizeYaw(yaw float32) float32 { return yaw }
func ClampPitch(pitch float32) float32 { return pitch }

func GenerateUUID() string {
 uuid := make([]byte, 16); _, err := rand.Read(uuid); if err != nil { return "" }
 uuid[6] = (uuid[6] & 0x0f) | 0x40; uuid[8] = (uuid[8] & 0x3f) | 0x80
 return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}
func GenerateUUIDUint64() uint64 { var uuid uint64; binary.Read(rand.Reader, binary.BigEndian, &uuid); return uuid }

// Base64Encode for JWT
func Base64Encode(input []byte) string {
 return strings.TrimRight(base64.URLEncoding.EncodeToString(input), "=")
}
// Base64Decode for JWT
func Base64Decode(input string) ([]byte, error) {
 if l := len(input) % 4; l > 0 { // Pad if necessary
  input += strings.Repeat("=", 4-l)
 }
 return base64.URLEncoding.DecodeString(input)
}

// KeepAlive sends a connected ping packet.
func (b *Bot) KeepAlive() error {
 var buf bytes.Buffer
 WriteUint8(&buf, RAKNET_CONNECTED_PING)
 WriteUint64LE(&buf, uint64(time.Now().UnixNano()/int64(time.Millisecond))) // Client timestamp
 packet := b.SerializePacket(RAKNET_CONNECTED_PING, buf.Bytes())
 return b.sendQueuePacket(packet, 0x05) // ReliableOrdered
}

// Reconnect attempts to reconnect the bot.
func (b *Bot) Reconnect() error {
 if b.config.Debug {
  fmt.Println("bedrock_rocket_bot: attempting reconnection...")
 }
 b.shutdown()
 time.Sleep(b.conn.timeout * 2) // Wait a bit longer before reconnecting
 b.mu.Lock()
 cfg := *b.config // Copy config
 b.mu.Unlock()
 return b.Start(cfg.Username, cfg.ServerAddr, cfg.ServerPort)
}

// IsConnected checks if the bot is currently connected.
func (b *Bot) IsConnected() bool {
 b.mu.Lock()
 defer b.mu.Unlock()
 return b.state.IsConnectedFlag
}

// GetLatency returns the estimated latency to the server. (Not implemented in minimal)
func (b *Bot) GetLatency() time.Duration {
 return 0
}

// FlushSendQueue immediately sends all queued packets.
func (b *Bot) FlushSendQueue() error { return nil } // Min. impl doesn't need explicit flush
func (b *Bot) PauseReceiving() {}
func (b *Bot) ResumeReceiving() {}

// LoadConfig loads configuration from a file (simplified).
func LoadConfig(path string) (*Config, error) {
 // For minimal build, always return default config.
 // A real implementation would parse JSON/YAML from 'path'
 return &Config{
  Username:         "RocketBot",
  ServerAddr:       "localhost", // Default for testing
  ServerPort:       19132,
  Protocol:         BEDROCK_PROTOCOL_VERSION,
  EnableEncryption: true, // Try to enable encryption
  Debug:            true,
 }, nil
}

// SaveState saves the current bot state. (Not implemented in minimal)
func (b *Bot) SaveState() error { return nil }
func (b *Bot) GetBotState() BotState { b.mu.Lock(); defer b.mu.Unlock(); return b.state }
func (b *Bot) UpdatePosition(pos Vector3) {}
func (b *Bot) UpdateRotation(yaw, pitch float32) {}
func (b *Bot) SetEntityID(id int64) {}
func (b *Bot) GetSessionID() uint32 { return 0 }


// Start initializes and connects the bot to the server.
func (b *Bot) Start(username string, server string, port int) error {
 b.mu.Lock()
 if b.IsConnected() {
  b.mu.Unlock()
  return errors
.New("bedrock_rocket_bot: bot already connected")
 }
 b.config.Username = username
 b.config.ServerAddr = server
 b.config.ServerPort = port
 addr := fmt.Sprintf("%s:%d", server, port)
 b.mu.Unlock()

 if b.config.Debug {
  fmt.Printf("bedrock_rocket_bot: connecting to %s...\n", addr)
 }

 var err error
 b.conn, err = DialRakNet(addr)
 if err != nil {
  return fmt.Errorf("bedrock_rocket_bot: failed to dial RakNet: %w", err)
 }
 b.mu.Lock()
 b.state.IsConnectedFlag = true
 b.connectionClosed = make(chan struct{}) // Reset channel for new connection
 b.mu.Unlock()

 // Start RakNet low-level loops
 go b.conn.rakNetPacketReaderLoop(b.cancelCtx)
 go b.conn.rakNetAckSenderLoop(b.cancelCtx)

 if b.config.Debug {
  fmt.Println("bedrock_rocket_bot: performing RakNet handshake (phase 1)...")
 }
 if err = b.SendOpenConnectionRequest1(); err != nil {
  return fmt.Errorf("bedrock_rocket_bot: failed to send OpenConnectionRequest1: %w", err)
 }
 reply1, err := b.ReceiveOpenConnectionReply1()
 if err != nil {
  return fmt.Errorf("bedrock_rocket_bot: failed to receive OpenConnectionReply1: %w", err)
 }
 if !b.ValidateHandshake(reply1) {
  return errors.New("bedrock_rocket_bot: failed OpenConnectionReply1 validation")
 }
 if b.config.Debug {
  fmt.Printf("bedrock_rocket_bot: RakNet handshake phase 1 (ServerGuid: %d, MTU: %d) complete. (phase 2)...\n", reply1.ServerGuid, reply1.MtuSize)
 }

 if err = b.SendOpenConnectionRequest2(reply1.ServerGuid, reply1.MtuSize); err != nil {
  return fmt.Errorf("bedrock_rocket_bot: failed to send OpenConnectionRequest2: %w", err)
 }
 // Wait for OpenConnectionReply2 / NewIncomingConnection
 if err := b.ReceiveOpenConnectionReply2(); err != nil {
  return fmt.Errorf("bedrock_rocket_bot: failed to receive OpenConnectionReply2: %w", err)
 }

 if b.config.Debug {
  fmt.Println("bedrock_rocket_bot: RakNet handshake completed. Sending Minecraft login...")
 }

 if err = b.SendLogin(); err != nil {
  return fmt.Errorf("bedrock_rocket_bot: failed to send login: %w", err)
 }
 if b.config.Debug {
  fmt.Println("bedrock_rocket_bot: waiting for login success (PlayStatus: 0)...")
 }
 if err = b.WaitForLoginSuccess(); err != nil {
  return fmt.Errorf("bedrock_rocket_bot: failed to wait for login success: %w", err)
 }

 // If we reach here, successful login and optional encryption setup has occurred.
 b.OnJoin()

 // Start main event loops after successful connection
 go b.mainPacketProcessorLoop()
 go b.keepAliveLoop()

 if b.config.Debug {
  fmt.Printf("bedrock_rocket_bot: bot '%s' successfully logged in to %s:%d (protocol %d).\n", username, server, port, b.config.Protocol)
 }
 return nil
}

// mainPacketProcessorLoop processes incoming Bedrock packets after login.
func (b *Bot) mainPacketProcessorLoop() {
 defer func() { fmt.Println("bedrock_rocket_bot: mainPacketProcessorLoop finished.") }()
 for {
  select {
  case <-b.cancelCtx.Done():
   return
  default:
   frame, err := b.conn.ReadFrame()
   if err != nil {
    if strings.Contains(err.Error(), "timeout") {
     continue
    }
    fmt.Printf("bedrock_rocket_bot: error reading frame in main loop: %v\n", err)
    b.Reconnect()
    return
   }
   
   // Decrypt if encryption is active
   var packetData []byte = frame
   if b.state.EncryptionEnabled && b.state.Decrypter != nil {
    decrypted, decErr := b.DecryptPayload(frame)
    if decErr == nil {
     packetData = decrypted
    } else {
     fmt.Printf("bedrock_rocket_bot: warning: failed to decrypt regular frame: %v\n", decErr)
    }
   }

   id, payload, err := b.DeserializePacket(packetData)
   if err != nil {
    //fmt.Printf("bedrock_rocket_bot: warning: failed to deserialize packet in main loop: %v\n", err) // Too chatty
    continue
   }
   b.processIncomingPacket(id, payload) // Dispatch to handlers
  }
 }
}

// processIncomingPacket handles a single deserialized Bedrock packet.
func (b *Bot) processIncomingPacket(id byte, payload []byte) {
 switch id {
 case MCBE_START_GAME_PACKET:
  if b.config.Debug {
   fmt.Printf("bedrock_rocket_bot: received Start Game Packet (0x%02x), payload len %d\n", id,len(payload))
  }
  // In a full implementation, parse StartGamePacket to get entity ID, spawn position etc.
  // For minimal, we just acknowledge its arrival.
  b.mu.Lock()
  b.state.EntityID = GenerateUUIDUint64() // Dummy ID
  b.state.RuntimeID = GenerateUUIDUint64() // Dummy Runtime ID
  b.state.CurrentPos = Vector3{X: 0, Y: 68, Z: 0} // Dummy pos
  b.mu.Unlock()
  // After Start Game, server usually sends Play Status 3 (Player Spawn)
  b.sendQueuePacket(b.SerializePacket(MCBE_PLAY_STATUS_PACKET, BuildUint32LEBytes(PLAY_STATUS_PLAYER_SPAWN)), 0x05)

 case MCBE_TEXT_PACKET:
  if len(payload) > 1 { // Ensure there's a type and some message content
   reader := bytes.NewReader(payload)
   _textType, _ := ReadUint8(reader)
   _needsTranslation, _ := ReadUint8(reader)
   sender, _ := ReadString(reader)
   message, _ := ReadString(reader)
   // Read other fields if needed
   b.OnChatMessage(sender, message)
  }
 case MCBE_PLAY_STATUS_PACKET:
  status, err := b.ParsePlayStatus(b.SerializePacket(MCBE_PLAY_STATUS_PACKET, payload))
  if err == nil && b.config.Debug {
   fmt.Printf("bedrock_rocket_bot: received PlayStatus: %d\n", status)
  }
 default:
  // Unknown or unhandled packet, dispatch to registered handlers if any.
  b.DispatchPacket(id, payload)
 }
}


// shutdown gracefully shuts down the bot.
func (b *Bot) shutdown() {
 if b.config.Debug {
  fmt.Println("bedrock_rocket_bot: shutting down bot...")
 }
 b.cancelFunc()
 if b.conn != nil {
  b.conn.CloseConnection()
 }
 b.mu.Lock()
 b.state.IsConnectedFlag = false
 if b.connectionClosed != nil {
  close(b.connectionClosed)
 }
 b.mu.Unlock()
 b.OnDisconnect()
}

// sendQueuePacket adds a packet to the send queue, applies encryption if active.
func (b *Bot) sendQueuePacket(packet []byte, reliability byte) error {
 var finalPacket []byte = packet
 if b.state.EncryptionEnabled && b.state.Encrypter != nil {
  encrypted, err := b.EncryptPayload(packet)
  if err != nil {
   return fmt.Errorf("bedrock_rocket_bot: failed to encrypt packet before sending: %w", err)
  }
  finalPacket = encrypted
 }

 // This is where RakNet encapsulation happens for the finalPacket
 return b.conn.SendFrame(finalPacket, reliability)
}

// KeepAliveLoop sends periodic keep-alive pings.
func (b *Bot) keepAliveLoop() {
 defer func() { fmt.Println("bedrock_rocket_bot: KeepAlive loop finished.") }()
 ticker := time.NewTicker(5 * time.Second) // Send ping every 5 seconds
 defer ticker.Stop()

 for {
  select {
  case <-b.cancelCtx.Done():
   return
  case <-ticker.C:
   if b.IsConnected() {
    if err := b.KeepAlive(); err != nil {
     fmt.Printf("bedrock_rocket_bot: KeepAlive error: %v\n", err)
     b.Reconnect()
     return
    }
   }
  }
 }
}

// GetConnectionClosedChan returns a channel that is closed when the bot disconnects.
func (b *Bot) GetConnectionClosedChan() <-chan struct{} {
 return b.connectionClosed
}

// --- Inventory and World Management (Stubs for minimal implementation) ---
func (b *Bot) GetInventory() []Item { return []Item{} }
func (b *Bot) EquipItem(slot int) error { return errors.New("bedrock_rocket_bot: EquipItem not implemented") }
func (b *Bot) DropItem(slot, count int) error { return errors.New("bedrock_rocket_bot: DropItem not implemented") }
func (b *Bot) PickupItem(itemID int) error { return errors.New("bedrock_rocket_bot: PickupItem not implemented") }
func (b *Bot) CraftRecipe(recipeID int) error { return errors.New("bedrock_rocket_bot: CraftRecipe not implemented") }
func (b *Bot) GetBlock(pos Vector3) Block { return Block{} }
func (b *Bot) SetBlock(pos Vector3, blockID int) error { return errors.New("bedrock_rocket_bot: SetBlock not implemented") }
func (b *Bot) BreakBlock(pos Vector3) error { return errors.New("bedrock_rocket_bot: BreakBlock not implemented") }
func (b *Bot) GetChunk(chunkX, chunkZ int32) (*Chunk, error) { return nil, errors.New("bedrock_rocket_bot: GetChunk not implemented") }
func (b *Bot) LoadChunk(chunkX, chunkZ int32) error { return errors.New("bedrock_rocket_bot: LoadChunk not implemented") }

// --- Security (Minimal ECDSA for JWT, AES forencryption) ---

// SignPacket signs data using ECDSA.
func (b *Bot) SignPacket(packet []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
 hash := sha256.Sum256(packet)
 r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
 if err != nil {
  return nil, fmt.Errorf("bedrock_rocket_bot: failed to sign packet: %w", err)
 }
 rBytes := r.FillBytes(make([]byte, 32))
 sBytes := s.FillBytes(make([]byte, 32))
 return append(rBytes, sBytes...), nil
}

// VerifySignature verifies an ECDSA signature.
func (b *Bot) VerifySignature(packet, signature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
 hash := sha256.Sum256(packet)
 curveBits := publicKey.Curve.Params().BitSize
 keyBytes := (curveBits + 7) / 8
 if len(signature) != 2*keyBytes {
  return false, errors.New("bedrock_rocket_bot: invalid signature length for verification")
 }

 r := new(big.Int).SetBytes(signature[:keyBytes])
 s := new(big.Int).SetBytes(signature[keyBytes:])

 return ecdsa.Verify(publicKey, hash[:], r, s), nil
}

// EncryptPayload encrypts data using the bot's active encryption stream.
func (b *Bot) EncryptPayload(payload []byte) ([]byte, error) {
 if b.state.Encrypter == nil {
  return nil, errors.New("bedrock_rocket_bot: encryption stream not initialized")
 }
 encrypted := make([]byte, len(payload))
 b.state.Encrypter.XORKeyStream(encrypted, payload)
 return encrypted, nil
}

// DecryptPayload decrypts data using the bot's active decryption stream.
func (b *Bot) DecryptPayload(data []byte) ([]byte, error) {
 if b.state.Decrypter == nil {
  return nil, errors.New("bedrock_rocket_bot: decryption stream not initialized")
 }
 decrypted := make([]byte, len(data))
 b.state.Decrypter.XORKeyStream(decrypted, data)
 return decrypted, nil
}

// Helper to build a uint32 LE byte slice
func BuildUint32LEBytes(v uint32) []byte {
 buf := new(bytes.Buffer)
 WriteUint32LE(buf, v)
 return buf.Bytes()
}

// ----------------------------------------------------------------------------------------------------
// Example main.go file to import and run this bot
// ----------------------------------------------------------------------------------------------------
/*
package main

import (
 "fmt"
 "time"
 "github.com/met465m/bedrock_rocket_bot" // Your module path
)

func main() {
 cfg, err := bedrock_rocket_bot.LoadConfig("") // Load default or provide a path
 if err != nil {
  fmt.Printf("Fatal: Error loading config: %v\n", err)
  return
 }

 // This is important: adjust the protocol for the server you are connecting to!
 // Example: for 1.20.70, it's 622. For 1.20.60, it's 621.
 cfg.Protocol = bedrock_rocket_bot.BEDROCK_PROTOCOL_VERSION // Make sure this matches your server!
 cfg.Username = "MyAwesomeBot"
 cfg.ServerAddr = "geo.hivebedrock.network" // Or your IP, e.g., "127.0.0.1"
 cfg.ServerPort = 19132 // Default Minecraft Bedrock port
 
 bot := bedrock_rocket_bot.NewBot(cfg)

 // Register specific handlers if needed (e.g., for custom chat logic)
 bot.RegisterPacketHandler(bedrock_rocket_bot.MCBE_START_GAME_PACKET, func(payload []byte) {
  fmt.Println("EVENT: Start Game packet received! Bot is in world.")
 })
 bot.registerEventListener("OnJoin", func(args ...interface{}) {
  fmt.Println("EVENT: Bot successfully joined and logged in!")
  go func() {
   time.Sleep(3 * time.Second) // Give server a moment
   if err := bot.SendChatMessage("Hello world from RocketBot!"); err != nil {
    fmt.Printf("Error sending initial chat message: %v\n", err)
   }
  }()
 })
 
 // Run the bot in a goroutine so main can wait for its completion.
 go func() {
  if err := bot.Start(cfg.Username, cfg.ServerAddr, cfg.ServerPort); err != nil {
   fmt.Printf("Fatal: Failed to start bot: %v\n", err)
   return
  }

  // Keep the bot running for a while, or until disconnected.
  // Main goroutine waits on connectionClosed channel.
  // If you want to perform actions, put them here after some delay.
 }()

 fmt.Println("Main: Waiting for bot to connect or disconnect...")
 <-bot.GetConnectionClosedChan() // Block until bot disconnects
 fmt.Println("Main: Bot disconnected. Exiting.")
}
*/
