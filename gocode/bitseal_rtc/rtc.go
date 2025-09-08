package rtc

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"bytes"

	"github.com/bsv-blockchain/go-sdk/message"
	aesgcm "github.com/bsv-blockchain/go-sdk/primitives/aesgcm"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"go.uber.org/zap"
)

// Constants
const (
	protoString = "BitSeal-RTC/1.0"
	tagSize     = 16
)

type HandshakeMsg struct {
	Proto string `json:"proto"`
	PK    string `json:"pk"`   // compressed hex
	Salt  string `json:"salt"` // 4 bytes hex
	Ts    int64  `json:"ts"`
}

// BuildHandshake creates and signs a handshake payload.
func BuildHandshake(selfPriv *ec.PrivateKey, peerPub *ec.PublicKey) ([]byte, []byte, []byte, error) {
	// 4-byte salt
	salt := make([]byte, 4)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, err
	}
	ts := time.Now().UnixMilli()
	pkHex := hex.EncodeToString(selfPriv.PubKey().Compressed())
	saltHex := hex.EncodeToString(salt)
	// Canonical JSON with deterministic field order
	rawStr := fmt.Sprintf("{\"proto\":\"%s\",\"pk\":\"%s\",\"salt\":\"%s\",\"ts\":%d}", protoString, pkHex, saltHex, ts)
	raw := []byte(rawStr)
	// Sign raw bytes directly per BRC-77
	// (digesting is done internally in the signing algorithm if required)
	// Keep consistent with TypeScript implementation which signs raw.

	sig, err := message.Sign(raw, selfPriv, peerPub)
	if err != nil {
		return nil, nil, nil, err
	}
	return raw, sig, salt, nil
}

// VerifyHandshake verifies peer handshake and returns peer pubkey & salt.
func VerifyHandshake(raw, sig []byte, selfPriv *ec.PrivateKey) (*ec.PublicKey, []byte, error) {
	// parse
	var msg HandshakeMsg
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, nil, err
	}
	if msg.Proto != protoString {
		return nil, nil, errors.New("protocol mismatch")
	}
	peerPubBytes, err := hex.DecodeString(msg.PK)
	if err != nil {
		return nil, nil, err
	}
	peerPub, err := ec.ParsePubKey(peerPubBytes)
	if err != nil {
		return nil, nil, err
	}
	ok, err := message.Verify(raw, sig, selfPriv)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, errors.New("signature invalid")
	}
	saltBytes, err := hex.DecodeString(msg.Salt)
	if err != nil {
		return nil, nil, err
	}
	return peerPub, saltBytes, nil
}

// Session represents an established BST2 session.
type Session struct {
	key        []byte // 32-byte AES key
	saltSend   []byte // 4 bytes – 用于本端发送
	saltRecv   []byte // 4 bytes – 用于解密对端数据
	seq        uint64 // send seq
	recvWindow *window
	peerPub    *ec.PublicKey // remote party's public key
	// no cipher.AEAD, use aesgcm helpers
}

type window struct {
	size   uint64
	maxSeq uint64
	bitmap uint64 // supports up to 64
}

// deriveKey derives 32-byte session key from shared secret + salts.
func deriveKey(shared, saltA, saltB []byte) []byte {
	// 为保证两端顺序一致，按字典序拼接 saltA、saltB。
	if bytes.Compare(saltA, saltB) > 0 {
		saltA, saltB = saltB, saltA
	}
	data := append(shared, saltA...)
	data = append(data, saltB...)
	return crypto.Sha256(data)
}

// NewSession creates session after both handshakes exchanged.
// If logger is nil, the function stays silent.
func NewSession(selfPriv *ec.PrivateKey, peerPub *ec.PublicKey, selfSalt, peerSalt []byte, logger *zap.Logger) (*Session, error) {
	sharedPoint, err := selfPriv.DeriveSharedSecret(peerPub)
	if err != nil {
		return nil, err
	}
	sharedBytes := sharedPoint.Compressed()
	// DEBUG: 可选日志
	if logger != nil {
		logger.Debug("derive input", zap.String("saltA", fmt.Sprintf("%x", selfSalt)), zap.String("saltB", fmt.Sprintf("%x", peerSalt)), zap.String("shared_first16", fmt.Sprintf("%x", sharedBytes[:16])))
	}
	key := deriveKey(sharedBytes, selfSalt, peerSalt)
	if logger != nil {
		logger.Debug("derive output", zap.String("key_first16", fmt.Sprintf("%x", key[:16])))
	}

	// no need to init AESGCM cipher here

	// initialize send sequence with random 64-bit value (seq_init)
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, err
	}
	initSeq := binary.BigEndian.Uint64(randBytes)

	return &Session{
		key:        key,
		saltSend:   selfSalt,
		saltRecv:   peerSalt,
		seq:        initSeq,
		recvWindow: &window{size: 64, maxSeq: 0, bitmap: 0},
		peerPub:    peerPub,
		// aead field removed
	}, nil
}

// EncodeRecord encrypts plaintext into a BST2 frame.
func (s *Session) EncodeRecord(plaintext []byte, flags byte) ([]byte, error) {
	s.seq++
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, s.seq)
	nonce := append(s.saltSend, seqBytes...)
	ad := append([]byte{flags}, seqBytes...)

	// Use optimized sdk implementation that returns ciphertext and tag separately.
	cipherTextOnly, tag, err := aesgcm.AESGCMEncrypt(plaintext, s.key, nonce, ad)
	if err != nil {
		return nil, err
	}
	length := uint32(1 + 8 + uint32(len(cipherTextOnly)) + tagSize)

	buf := make([]byte, 4+1+8+len(cipherTextOnly)+tagSize)
	binary.BigEndian.PutUint32(buf[0:4], length)
	buf[4] = flags
	copy(buf[5:13], seqBytes)
	copy(buf[13:13+len(cipherTextOnly)], cipherTextOnly)
	copy(buf[13+len(cipherTextOnly):], tag)
	return buf, nil
}

// DecodeRecord decrypts frame and returns plaintext.
func (s *Session) DecodeRecord(frame []byte) ([]byte, error) {
	if len(frame) < 4+1+8+tagSize {
		return nil, errors.New("frame too short")
	}
	length := binary.BigEndian.Uint32(frame[:4])
	if int(length) != len(frame[4:]) {
		return nil, fmt.Errorf("length mismatch: %d vs %d", length, len(frame[4:]))
	}
	flags := frame[4]
	seq := binary.BigEndian.Uint64(frame[5:13])
	// replay window check
	if !s.recvWindow.accept(seq) {
		return nil, errors.New("replay or old packet")
	}
	cipherTextOnly := frame[13 : len(frame)-tagSize]
	tag := frame[len(frame)-tagSize:]
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)
	nonce := append(s.saltRecv, seqBytes...)
	ad := append([]byte{flags}, seqBytes...)

	plain, err := aesgcm.AESGCMDecrypt(cipherTextOnly, s.key, nonce, ad, tag)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func (w *window) accept(seq uint64) bool {
	if seq > w.maxSeq {
		shift := seq - w.maxSeq
		if shift >= w.size {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.maxSeq = seq
		return true
	}
	offset := w.maxSeq - seq
	if offset >= w.size {
		return false
	}
	if (w.bitmap>>offset)&1 == 1 {
		return false
	}
	w.bitmap |= (1 << offset)
	return true
}

// PeerPub returns peer's public key.
func (s *Session) PeerPub() *ec.PublicKey {
	return s.peerPub
}
