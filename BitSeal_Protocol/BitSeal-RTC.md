# BitSeal-RTC – Protocol Design Draft

> A lightweight end-to-end security layer for WebRTC DataChannels, embracing the BitSeal philosophy and requiring **no pre-registration**.

---
## 1. Overview
BitSeal-RTC 将安全逻辑拆为两层：

| Layer | Name | Purpose |
|------|------|------|
| **BSH1** | BitSeal Handshake Layer v1 | Mutual authentication and key agreement via ECDSA/Schnorr signatures + ECDH-derived session keys |
| **BST2** | BitSeal Secure Transport Layer v2 | AEAD symmetric encryption using the derived key, 64-bit sequence numbers for anti-replay, supports zero-RTT low-latency large messages |

> By default, traffic uses the WebRTC/SCTP **reliable** mode where SCTP handles fragmentation and reassembly. Partially-reliable modes can be negotiated via a future `flags` field.

---
## 2. BSH1 – Handshake Layer

1. **Handshake message format** (JSON or CBOR):
   ```json
   {
     "proto": "BitSeal-RTC/1.0",
     "pk": "<33B compressed>",
     "salt": "<4B hex>",
     "ts": 1700000123456,
     "nonce": "128-bit hex"
   }
   ```
2. Each side generates its own `salt_A / salt_B` and a random `nonce`, then computes
   ```
   digest = SHA256(canonical(handshake_msg))   // canonical = 字段按 proto→pk→salt→ts 排序，且无空格
   sig    = SignedMessage.sign(digest, SK_self, PK_peer)
   ```
3. Exchange `{handshake_msg, sig}`; after validating the peer's signature:
   ```text
   shared_secret = ECDH(SK_self, PK_peer)

   // IMPORTANT: sort the two 4-byte salts **lexicographically (byte-wise)**
   // before concatenation, so both peers feed HKDF with identical input.
   // e.g. 0x01 02 03 04 < 0x05 06 07 08 ⇒ salt_lo = salt_A, salt_hi = salt_B
   key_session   = HKDF(shared_secret, salt_lo || salt_hi)

   // Per-direction nonces use each side's own salt:
   salt_send     = salt_self    // 4B → outbound frames
   salt_recv     = salt_peer    // 4B → decrypt inbound frames

   seq_init      = random 64-bit   // 独立于方向
   ```
4. Handshake completes – switch to **BST2**.

---
## 3. BST2 – Transport Layer

### 3.1 Nonce construction
```
Nonce = salt_session(4B) || seq(8B)
```
* `salt_session` is fixed per direction and decided during the handshake.
* `seq` is a 64-bit monotonic counter that may start at a random offset and **MUST NOT wrap around**; re-handshake before overflow.

### 3.2 AEAD choice
* Recommended: `ChaCha20-Poly1305` (mobile) or `AES-256-GCM` (desktop).
* Auth tag size is 16 bytes for both.

### 3.3 Record format
```
+---------+---------+------------+-------------+-----------+
| len(4B) | flags(1)| seq(8B)    | ciphertext  | tag(16B)  |
+---------+---------+------------+-------------+-----------+
```
* **len** – total length of `flags || seq || ciphertext || tag` in network byte order.
* **flags** – bit0=0 for reliable, 1 for unreliable; bit1 reserved…
* **Associated Data (AD)** = `flags || seq`.
* **ciphertext**：`AEAD_Encrypt(key_session, Nonce, plaintext, AD)` 的输出。

### 3.4 Send path
```
seq += 1
nonce = salt || seq
cipher, tag = AEAD_Encrypt(key, nonce, plaintext, AD)
frame = len || flags || seq || cipher || tag
DataChannel.send(frame)
```
> **Transparent fragmentation** – WebRTC/SCTP will fragment `frame` to MTU-sized chunks; all chunks share the same `seq`. The receiver reassembles before decryption.

### 3.5 Receiver sliding window
```text
window_size = 64     // Tunable; large enough for typical jitter, can be increased
max_seq     = -1
bitmap      = 0
```
处理流程：
1. 若 `seq < max_seq - window_size + 1` ⇒ 丢弃（过旧 / 重放）。
2. 若 `seq > max_seq`：窗口右移 `shift = seq - max_seq`，`bitmap <<= shift`，再 `bitmap |= 1`，更新 `max_seq`。
3. 否则落在窗口内：若 `bitmap` 已标 1 ⇒ 丢弃重复；否则置位。
4. 尝试 `AEAD_Decrypt`；失败即丢包。

### 3.6 Application-level fragmentation (Profile L, up to 64 MiB)

If a single plaintext exceeds ≈60 KiB, SCTP's `MaxMessageSize` and browser buffers become bottlenecks.
BST2 specifies an optional **application-layer fragmentation** on top of the record layer, with a default "L" profile:

| Parameter | Value | Description |
|-------------------|--------------|------|
| `FRAG_SIZE`       | 16 KiB       | Plaintext size per fragment, balancing MTU and overhead |
| `MAX_FRAGS`       | 4 096        | Maximum number of fragments per message |
| Max message size  | 64 MiB       | `FRAG_SIZE × MAX_FRAGS` |

**Fragment header (8 B, network byte order)**
```
+---------+----------+---------+------------+
|flags(1B)|msgID(3B) |fragID(2)|total(2)    |
+---------+----------+---------+------------+
```
* `msgID`: 24-bit logical message ID, wraps around;
* `fragID / total`：当前片序号与总片数；
* `flags.bit0`：末片标记（目前实现仅作提示，解密流程与前片相同）。

**设计取舍：每片独立携带 16 B Auth-Tag**
The current Go / TypeScript implementations call `AEAD_Encrypt` per fragment at the BST2 layer and send `cipher || tag` together:
1. 发送端切片 → 逐片 `seq+=1` → Seal → 立即发出。  
2. 接收端收到任意片即可先走 3.5 的重放窗口，再立即解密与验证 Tag，及时丢弃伪造数据。  
3. 解密成功的片缓存于 `{msgID, fragID}` 表；当 `received == total` 时按序拼接得到完整明文。  

Although per-fragment tags cost ≈0.10 % extra bandwidth they greatly simplify implementation and improve loss resilience, therefore they are **recommended and default** for Profile L. A future higher profile (e.g. "L+") may move the tag to the last fragment for extreme bandwidth savings.

> Profile L already covers 99 % of file/image transfers. For larger messages increase `FRAG_SIZE` to 32 KiB or relax `MAX_FRAGS` (the 8-B header scales up to ≈1 GiB).

---
## 4. Re-keying & Session Updates
* When `seq` ≥ 2⁶⁴-1 or the session exceeds 24 h ⇒ trigger a new BSH1 handshake.
// KeyUpdate left for future extension; not covered here.

---
## 5. Optional BSC3 – Chained Checkpoints
For **non-repudiation**
1. 每隔 *N* 秒将 `last_seq || SHA256(transcript)` 签名后发送 `checkpoint` 帧。
2. 这样可在离线审计时证明整个窗口流量未被篡改。

---
## 6. Security Notes
1. **Nonce 不重用**：`salt+seq` 组合必须唯一；任何方向回绕前强制换密钥。
2. **时间同步**：`ts` 仅用于握手防回放，可宽容 ±300 s。
3. **帧界定**：若使用 DataChannel 的"message"模式，可省 `len` 字段；但"binary stream"模式下必须携带长度。
4. **回放窗口**：`window_size` 越大，内存越多；64 位已能覆盖常见网络抖动，如需更大可自行调整。

---
## 7. Comparison with Existing Protocols
| Protocol | Handshake | Encryption | Anti-replay | Highlights |
|-------|-------|-------|-----------|-------|
| DTLS | X.509 / PSK | AEAD + epoch/seq | 是 | 证书链复杂，4 次 RTT |
| QUIC | TLS 1.3 | AEAD + pkt num | 是 | 0-RTT，面向连接 |
| **BitSeal-RTC** | BSH1 (ECDSA/Schnorr) | AEAD + 64-bit seq | Yes | CA-less, P2P, one RTT |

---
## 8. Reference Implementations
* TypeScript: `tscode/ts-sdk/...` provides a WebRTC adapter;
* Go: `gocode/go-sdk/...` plans to add an `rtc` sub-package.

> This is an initial draft – feedback and PRs are highly welcome. 