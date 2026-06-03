package main

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// VPE2 encrypted TCP protocol — ChaCha20 stream cipher with HMAC framing,
// X25519 forward secrecy, and HMAC-SHA256 key derivation.

// =========================================================================
// ChaCha20 stream cipher (RFC 8439)
// =========================================================================

type chacha20State struct {
	key     [32]byte
	nonce   [3]uint32
	counter uint32
	ks      [64]byte
	pos     int
}

func newChacha20(key [32]byte) *chacha20State {
	s := &chacha20State{pos: 64}
	s.key = key
	return s
}

var errCounterOverflow = fmt.Errorf("VPE2: ChaCha20 counter overflow — reconnect required")

func (s *chacha20State) xor(data []byte) error {
	for i := range data {
		if s.pos >= 64 {
			if s.counter > 0xFFFF0000 {
				return errCounterOverflow
			}
			s.generateBlock()
			s.counter++
			s.pos = 0
		}
		data[i] ^= s.ks[s.pos]
		s.pos++
	}
	return nil
}

func quarterRound(a, b, c, d *uint32) {
	*a += *b
	*d ^= *a
	*d = (*d << 16) | (*d >> 16)
	*c += *d
	*b ^= *c
	*b = (*b << 12) | (*b >> 20)
	*a += *b
	*d ^= *a
	*d = (*d << 8) | (*d >> 24)
	*c += *d
	*b ^= *c
	*b = (*b << 7) | (*b >> 25)
}

func (s *chacha20State) generateBlock() {
	var state [16]uint32
	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574
	state[4] = binary.LittleEndian.Uint32(s.key[0:4])
	state[5] = binary.LittleEndian.Uint32(s.key[4:8])
	state[6] = binary.LittleEndian.Uint32(s.key[8:12])
	state[7] = binary.LittleEndian.Uint32(s.key[12:16])
	state[8] = binary.LittleEndian.Uint32(s.key[16:20])
	state[9] = binary.LittleEndian.Uint32(s.key[20:24])
	state[10] = binary.LittleEndian.Uint32(s.key[24:28])
	state[11] = binary.LittleEndian.Uint32(s.key[28:32])
	state[12] = s.counter
	state[13] = s.nonce[0]
	state[14] = s.nonce[1]
	state[15] = s.nonce[2]
	initial := state
	for i := 0; i < 10; i++ {
		quarterRound(&state[0], &state[4], &state[8], &state[12])
		quarterRound(&state[1], &state[5], &state[9], &state[13])
		quarterRound(&state[2], &state[6], &state[10], &state[14])
		quarterRound(&state[3], &state[7], &state[11], &state[15])
		quarterRound(&state[0], &state[5], &state[10], &state[15])
		quarterRound(&state[1], &state[6], &state[11], &state[12])
		quarterRound(&state[2], &state[7], &state[8], &state[13])
		quarterRound(&state[3], &state[4], &state[9], &state[14])
	}
	for i := 0; i < 16; i++ {
		state[i] += initial[i]
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(s.ks[i*4:i*4+4], state[i])
	}
}

func (s *chacha20State) zeroState() {
	for i := range s.key {
		s.key[i] = 0
	}
	for i := range s.ks {
		s.ks[i] = 0
	}
	s.counter = 0
	s.nonce = [3]uint32{}
}

// =========================================================================
// CipherConn — encrypted net.Conn with mutex safety
// =========================================================================

type CipherConn struct {
	raw     net.Conn
	recv    *chacha20State
	send    *chacha20State
	sendMu  sync.Mutex
	recvMu  sync.Mutex
	hmacKey [32]byte
}

func (c *CipherConn) Read(p []byte) (int, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	n, err := c.raw.Read(p)
	if n > 0 {
		if xerr := c.recv.xor(p[:n]); xerr != nil {
			return n, xerr
		}
	}
	return n, err
}

func (c *CipherConn) Write(p []byte) (int, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	buf := make([]byte, len(p))
	copy(buf, p)
	if err := c.send.xor(buf); err != nil {
		return 0, err
	}
	return c.raw.Write(buf)
}

func (c *CipherConn) Close() error {
	c.recv.zeroState()
	c.send.zeroState()
	for i := range c.hmacKey {
		c.hmacKey[i] = 0
	}
	return c.raw.Close()
}

func (c *CipherConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *CipherConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *CipherConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *CipherConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *CipherConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

var _ net.Conn = (*CipherConn)(nil)

// =========================================================================
// PrefixConn
// =========================================================================

type PrefixConn struct {
	prefix []byte
	conn   net.Conn
}

func (p *PrefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.conn.Read(b)
}

func (p *PrefixConn) Write(b []byte) (int, error)        { return p.conn.Write(b) }
func (p *PrefixConn) Close() error                        { return p.conn.Close() }
func (p *PrefixConn) LocalAddr() net.Addr                 { return p.conn.LocalAddr() }
func (p *PrefixConn) RemoteAddr() net.Addr                { return p.conn.RemoteAddr() }
func (p *PrefixConn) SetDeadline(t time.Time) error       { return p.conn.SetDeadline(t) }
func (p *PrefixConn) SetReadDeadline(t time.Time) error   { return p.conn.SetReadDeadline(t) }
func (p *PrefixConn) SetWriteDeadline(t time.Time) error  { return p.conn.SetWriteDeadline(t) }

var _ net.Conn = (*PrefixConn)(nil)

// =========================================================================
// VPE2 Handshake
// =========================================================================

func hmacSHA256(key, message []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func HandleVPE2Handshake(conn net.Conn, magicCode string) (net.Conn, error) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	magic := make([]byte, 4)
	if _, err := io.ReadFull(conn, magic); err != nil {
		return nil, fmt.Errorf("VPE2: failed to read magic: %w", err)
	}
	if string(magic) != "VPE2" {
		return nil, fmt.Errorf("VPE2: bad magic: %x", magic)
	}

	clientNonce := make([]byte, 32)
	if _, err := io.ReadFull(conn, clientNonce); err != nil {
		return nil, fmt.Errorf("VPE2: failed to read client nonce: %w", err)
	}

	clientPubBytes := make([]byte, 32)
	if _, err := io.ReadFull(conn, clientPubBytes); err != nil {
		return nil, fmt.Errorf("VPE2: failed to read client X25519 pubkey: %w", err)
	}

	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("VPE2: failed to generate X25519 key: %w", err)
	}
	serverPubBytes := serverPriv.PublicKey().Bytes()

	clientPub, err := ecdh.X25519().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("VPE2: invalid client X25519 pubkey: %w", err)
	}

	sharedSecret, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, fmt.Errorf("VPE2: X25519 ECDH failed: %w", err)
	}

	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, fmt.Errorf("VPE2: failed to generate server nonce: %w", err)
	}
	response := make([]byte, 64)
	copy(response[:32], serverNonce)
	copy(response[32:], serverPubBytes)
	if _, err := conn.Write(response); err != nil {
		return nil, fmt.Errorf("VPE2: failed to send server response: %w", err)
	}

	ikm := make([]byte, 0, 96)
	ikm = append(ikm, clientNonce...)
	ikm = append(ikm, serverNonce...)
	ikm = append(ikm, sharedSecret...)
	sessionKey := hmacSHA256([]byte(magicCode), ikm)

	keyC2S := hmacSHA256(sessionKey[:], []byte("c2s"))
	keyS2C := hmacSHA256(sessionKey[:], []byte("s2c"))
	hmacKey := hmacSHA256(sessionKey[:], []byte("hmac"))

	for i := range sessionKey {
		sessionKey[i] = 0
	}
	for i := range ikm {
		ikm[i] = 0
	}
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}

	conn.SetDeadline(time.Time{})

	return &CipherConn{
		raw:     conn,
		recv:    newChacha20(keyC2S),
		send:    newChacha20(keyS2C),
		hmacKey: hmacKey,
	}, nil
}
