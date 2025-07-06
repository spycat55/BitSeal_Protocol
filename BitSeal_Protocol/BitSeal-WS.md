# BitSeal-WS – Protocol Specification (Draft v0.1)

> 基于 BitSeal-WEB 的无注册握手机制与 BitSeal-RTC 的 AEAD 加密传输层，将两者融合于 HTTP Upgrade / WebSocket 场景，兼顾浏览器友好与低延迟全双工。

---
## 1. 概览
BitSeal-WS 通过一次 **HTTPS 握手** 完成双向身份验证与会话密钥协商，随后使用 `Upgrade: websocket` 切换至全双工通道。在 WebSocket 数据帧内沿用 BitSeal-RTC **BST2** 的 AEAD 加密、64 位序号与重放窗口，提供端到端保密与完整性校验。

* 握手层：BitSeal-WEB（BRC-77 签名 + Timestamp + Nonce）
* 传输层：BitSeal-RTC BST2（ChaCha20-Poly1305 / AES-256-GCM，64-bit `seq`）
* 无需 CA / PSK 预注册，天然支持 CDN 与负载均衡。

---
## 2. 角色与密钥
| 角色 | 密钥 | 说明 |
|------|------|------|
| **Client** | 长期私钥 `SK_C`（local 保存）| 浏览器 / App |
| **Server** | 长期私钥 `SK_S` | API Gateway 或业务后端 |

与 BitSeal-WEB 相同，推荐在签名时将 `PK_S` 作为 *recipient public key* 以增强防钓鱼能力。

---
## 3. 协议流程总览
```
┌────────────Client─────────────┐      ┌─────────────Server──────────────┐
│ 1. POST /ws/handshake ------------------------------►                 │
│    (BitSeal-WEB headers)                                            │
│ ◄--------------------------------------------- 2. 200 OK + Sig │
│ 3. GET /ws/socket  (Upgrade: websocket)  --------------------------►│
│ ◄-------------------------------------------- 4. 101 Switching │
│ 5. BST2 加密帧  <==============================================>│
└──────────────────────────────────────────┘      └─────────────────────┘
```
步骤说明：
1. Client 发送 **HTTPS POST** 握手消息，Headers 与 Canonical String 继承 BitSeal-WEB；Body 为固定 JSON（见 §4）。
2. Server 校验签名后以自身私钥签名响应，并返回 **JWT 令牌** `token` 与服务器侧盐值 `salt_s`。
3. Client 随即（或复用连接）发起 `GET /ws/socket`，携带 `Upgrade: websocket` 与 `Sec-WebSocket-Protocol: BitSeal-WS/1.0,<token>`（子协议第二项为 JWT）。
4. Server 验证 **JWT** 后返回 `101 Switching Protocols`。
5. 双方进入 **BST2** 加密传输层，所有 WebSocket `binary` 帧均按 §6 格式封装。

---
## 4. 握手消息（H1）
### 4.1 请求体
```json
{
  "proto": "BitSeal-WS/1.0",
  "pk": "<33B compressed>",
  "salt": "<4B hex>",
  "nonce": "<128-bit hex>"
}
```
Digest 构造：沿用 BitSeal-WEB 六行 Canonical String，但 *Body* 为上述 JSON 文本的 **SHA-256**。签名格式、Header 字段与 BitSeal-WEB 完全一致。

### 4.2 响应体
```json
{
  "token": "<JWT string>",
  "salt_s": "<4B hex>",
  "ts": 1700000123456,
  "nonce": "<client_nonce>"  // 回显
}
```
Server 同样以 BitSeal-WEB 方式在 `X-BKSA-Sig` 中附带签名。

### 4.3 会话密钥派生
```
shared_secret = ECDH(SK_self, PK_peer)
key_session   = HKDF(shared_secret, salt || salt_s)
salt_session  = salt || salt_s    // 4B (client→srv) + 4B (srv→client)
seq_init      = random 64-bit     // 各方向独立
```

### 4.4 JWT 令牌格式
* Header: `{ "alg":"ES256K", "typ":"JWT" }`
* Payload (示例)：
```json
{
  "addr": "bc1q...",      // 客户端地址（由 pk 推导）
  "salt_s": "1a2b3c4d",   // 服务器侧 4B 盐
  "iat": 1700000123456,    // 签发时间，毫秒
  "exp": 1700000150000,    // 过期（≤60 s 建议）
  "nonce": "c4b7e6d9..."   // 同握手
}
```
JWT 签名算法：`ES256K`（secp256k1，低-s），使用 `SK_S` 进行签名，客户端验证公钥 `PK_S`。

---
## 5. WebSocket Upgrade
Client 在 `GET /ws/socket` 请求头加入：
```
Sec-WebSocket-Protocol: BitSeal-WS/1.0,<token>
```
Server 解析第二个子协议条目获取 **JWT**，验证通过后回 `101 Switching Protocols`，可只回显 `Sec-WebSocket-Protocol: BitSeal-WS/1.0`（RFC 6455 允许子集）。

> **规范要求**：`token` **必须**通过子协议第二项携带；不再支持 URL 查询、Cookie、Authorization 头等其他方式。

示例：

```js
// Browser / Node 客户端
const ws = new WebSocket('wss://api.example.com/ws/socket', ['BitSeal-WS/1.0', token])

// Go 服务器端 (golang.org/x/net/websocket)
protos := strings.Split(req.Header.Get("Sec-WebSocket-Protocol"), ",")
token := strings.TrimSpace(protos[1])
```

---
## 6. BST2 – 加密帧格式
与 BitSeal-RTC §3 完全一致：
```
+---------+---------+------------+-------------+-----------+
| len(4B) | flags(1)| seq(8B)    | ciphertext  | tag(16B)  |
+---------+---------+------------+-------------+-----------+
```
* **Nonce** = `salt_session(4B)` || `seq(8B)`  
* **AD**    = `flags || seq`
* **AEAD**  = `ChaCha20-Poly1305`（移动端默认）或 `AES-256-GCM`（桌面）

浏览器可使用 `WebCrypto` 的 `crypto.subtle.encrypt / decrypt`；Node.js 参考 `node:crypto` 模块。

---
## 7. 重放窗口与分片
BST2 在每个方向维护 64 位 `seq`、窗口大小默认为 64，算法同 BitSeal-RTC §3.5。若明文超过 ≈60 KiB，可启用 **Profile L**（§3.6）。

---
## 8. 会话管理
* 当 `seq` ≥ 2⁶⁴-1 或连接持续 ≥ 24 h ⇒ Client 主动重新执行握手并建立新 WebSocket。
* Server 可随时发送 WebSocket Close Code **4403**（会话过期）提示 Client 重新握手。

---
## 9. 错误码
| WebSocket Close Code | 对应 HTTP / B 系列 | 说明 |
|----------------------|--------------------|------|
| 4401 | 401 / B002 | 签名验证失败 |
| 4403 | 401 / B003 | 会话过期 / 时间戳无效 |
| 4409 | 402 / B010 | 匿名额度超限，需 KYC |
| 4499 | 500 / B099 | 服务器内部错误 |

---
## 10. 安全性要点
1. **无注册即用**：握手沿用 BitSeal-WEB 头部，可被 CDN / WAF 解析，部署成本低。
2. **端到端加密**：Upgrade 之后所有数据帧均经 AEAD 保护，TLS 仍建议启用以防降级攻击。
3. **重放防护**：64 bit 序号 + 滑动窗口；`Nonce = salt+seq` 保证唯一。
4. **防钓鱼**：在签名时使用 `PK_S` 作为 recipient，可防止恶意中间人伪造服务器。

---
## 11. 参考实现
* **TypeScript**：`tscode/ts-sdk/ws`（规划中，基于 `isomorphic-ws` + WebCrypto）
* **Go**：`gocode/go-sdk/ws`（规划中，基于 `x/net/websocket` + `golang.org/x/crypto`）

> 本规范为草案，版本 **v0.1**，欢迎 Issue / PR 提出改进意见。 