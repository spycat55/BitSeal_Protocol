# BitSeal-RTC – Future Extension Proposals

This document lists potential enhancements that are currently out of scope but worth considering for future releases.

## 1. KeyUpdate (In-session Re-keying)
Rotate the session key without interrupting the data stream.

1. Either side sends a control frame `KEY_UPDATE { newSalt }`;
2. The peer responds with `KEY_UPDATE_ACK { newSalt }`;
3. Both parties derive a new `key_session'` by running HKDF over the old `shared_secret` + `newSalt`, then reset `seq` to zero;
4. The old key is kept alive for a short replay window and then destroyed.

Typical triggers:
* `seq` approaches `2^64-1`;
* The session lasts longer than 24 h;
* Manually increase forward secrecy.

## 2. ChaCha20-Poly1305 Support
To better serve mobile and WebCrypto environments, add ChaCha20-Poly1305 alongside AES-GCM. Negotiation:

* Add a `cipher` field to `handshake_msg` with values `aesgcm` or `chacha20`.

## 3. BSC3 – Chained Checkpoints (Non-Repudiation)
Periodically send a signed `checkpoint` frame:

```
checkpoint = Sign(SK_self, last_seq || SHA256(transcript))
```

During offline auditing this proves that the whole window of traffic has not been tampered with.

## 4. Unreliable Transport Flag
When `flags.bit0 == 1` use a WebRTC `unreliable` sub-channel, useful for real-time voice/video control messages.

## 5. Larger Replay Window
If a `window_size` of 128 or more is desired, expand the bitmap to two `uint64` words or adopt a bitset.

## 6. Tag-Merged High Profile (L+)
Implement “tag only in the last fragment” to save ~94 % of Auth-Tag overhead.
The receiver caches ciphertext fragments until the last one arrives, then decrypts and verifies them in one shot.

---
These proposals are not yet scheduled. Community feedback and PRs are welcome!