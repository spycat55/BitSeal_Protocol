package bitsealws

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	rtc "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_rtc"
	bsweb "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_web"

	"golang.org/x/net/websocket"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// BitSealWSConn 封装了 x/net/websocket.Conn，并在读写时自动进行 BST2 编解码。
// 发送方需先 EncodeRecord，接收方需 DecodeRecord，本结构体内部自动处理。
type BitSealWSConn struct {
	Conn    *websocket.Conn
	Session *rtc.Session
}

// Write 加密并发送明文数据。
func (c *BitSealWSConn) Write(plain []byte) error {
	if c == nil || c.Conn == nil || c.Session == nil {
		return errors.New("BitSealWSConn nil")
	}
	frame, err := c.Session.EncodeRecord(plain, 0)
	if err != nil {
		return err
	}
	return websocket.Message.Send(c.Conn, frame)
}

// Read 接收并解密下一帧，返回明文。
func (c *BitSealWSConn) Read() ([]byte, error) {
	if c == nil || c.Conn == nil || c.Session == nil {
		return nil, errors.New("BitSealWSConn nil")
	}
	var frame []byte
	if err := websocket.Message.Receive(c.Conn, &frame); err != nil {
		return nil, err
	}
	plain, err := c.Session.DecodeRecord(frame)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// Close 关闭底层 websocket 连接。
func (c *BitSealWSConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

// ConnectBitSealWS 完成客户端两步握手并建立 BST2 会话，返回包装后的连接。
//  1. HTTP POST /ws/handshake – BitSeal-WEB 签名请求
//  2. WebSocket Upgrade /ws/socket – 子协议携带 SimpleToken
//
// wsURL 形如 wss://host/ws/socket
func ConnectBitSealWS(clientPriv *ec.PrivateKey, serverPub *ec.PublicKey, wsURL string) (*BitSealWSConn, error) {
	// ---------- 衍生 HTTP 基地址 ----------
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, fmt.Errorf("wsURL parse: %w", err)
	}
	httpBase := &url.URL{Scheme: "http", Host: u.Host}
	if u.Scheme == "wss" {
		httpBase.Scheme = "https"
	}

	// ---------- Step-1 生成握手请求 ----------
	saltC, err := randomSalt4Hex()
	if err != nil {
		return nil, err
	}
	body, signedHeaders, err := BuildHandshakeRequest(clientPriv, serverPub, saltC, "")
	if err != nil {
		return nil, err
	}

	// HTTP POST /ws/handshake
	handshakeURL := httpBase.String() + "/ws/handshake"
	req, err := http.NewRequest(http.MethodPost, handshakeURL, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	for k, v := range signedHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("handshake http %d: %s", resp.StatusCode, string(b))
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	respBodyStr := string(respBodyBytes)

	// 收集并规范化响应头（http 包会自动 Canonicalize 名称，VerifyRequest 需要精确大小写）
	hdr := map[string]string{
		"X-BKSA-Protocol":  resp.Header.Get("X-BKSA-Protocol"),
		"X-BKSA-Sig":       resp.Header.Get("X-BKSA-Sig"),
		"X-BKSA-Timestamp": resp.Header.Get("X-BKSA-Timestamp"),
		"X-BKSA-Nonce":     resp.Header.Get("X-BKSA-Nonce"),
	}

	// 验证服务器签名
	ok, err := bsweb.VerifyRequest("POST", "/ws/handshake", "", respBodyStr, hdr, clientPriv)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("server BitSeal signature invalid")
	}

	// 解析 JSON 响应
	var obj struct {
		Token string `json:"token"`
		SaltS string `json:"salt_s"`
		Ts    int64  `json:"ts"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(respBodyBytes, &obj); err != nil {
		return nil, err
	}

	// 验证 SimpleToken
	if _, err := VerifyToken(obj.Token, serverPub); err != nil {
		return nil, fmt.Errorf("token verify: %w", err)
	}

	// ---------- Step-2 WebSocket Upgrade ----------
	origin := &url.URL{Scheme: "http", Host: u.Host}
	if u.Scheme == "wss" {
		origin.Scheme = "https"
	}
	cfg, err := websocket.NewConfig(wsURL, origin.String())
	if err != nil {
		return nil, err
	}
	cfg.Protocol = []string{"BitSeal-WS.1", obj.Token}
	wsConn, err := websocket.DialConfig(cfg)
	if err != nil {
		return nil, err
	}

	// ---------- 建立 BST2 会话 ----------
	saltCBytes, _ := hex.DecodeString(saltC)
	saltSBytes, _ := hex.DecodeString(obj.SaltS)
	sess, err := rtc.NewSession(clientPriv, serverPub, saltCBytes, saltSBytes)
	if err != nil {
		wsConn.Close()
		return nil, err
	}

	return &BitSealWSConn{Conn: wsConn, Session: sess}, nil
}

// randomSalt4Hex 生成 4 字节随机盐（8 字符 hex）。
func randomSalt4Hex() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
