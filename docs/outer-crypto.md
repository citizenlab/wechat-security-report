# Outer layer of encryption

The outer layer of encryption used by WeChat can be summarized as TLS-like but with **heavy** use of 0-RTT resumption.

Shortlinks always must use 0-RTT resumption by design, since the transport is encoded in a single HTTP POST request and response, and WeChat makes extremely heavy use of Shortlink traffic.

## Overview
When opened, WeChat will send one Longlink `ClientHello` and one Shortlink `ClientHello`. After these handshakes, the app can start sending and receiving data, either on the long-lived Longlink by sending `Data` records, or by creating new Shortlink connections to send `EarlyData`.

Below, for demonstration purposes we show abbreviated versions of network packets. Full annotations of the MMTLS network layer wire format can be found in [mmtls-network-format.md](mmtls-network-format.md).

## Handshake

The initial handshakes for Longlink and Shortlink are similar, so we condense them into one section.

WeChat sends a `ClientHello` packet over both Longlink and Shortlink:
```
16 f1 04 (Handshake Record header) . . .
01 04 f1 (ClientHello) . . .
08 cd 1a 18 f9 1c . . . (ClientRandom) . . .
00 0c c2 78 00 e3 . . . (Resumption Ticket from psk.key) . . .
04 0f 1a 52 7b 55 . . . (Client public key) . . .
```

The client then recieves a `ServerHello` from the server.

```
16 f1 04 (Handshake Record header) . . .
02 04 f1 (ServerHello) . . .
2b a6 88 7e 61 5e 27 eb  . . . (ServerRandom) . . .
04 fa e3 dc 03 4a 21 d9 . . . (Server public key) . . .
16 f1 04 (Handshake Record header) . . .
b8 79 a1 60 be 6c . . . (ENCRYPTED server certificate) . . .
16 f1 04 (Handshake Record header) . . .
1a 6d c9 dd 6e f1 . . . (ENCRYPTED NEW resumption ticket) . . .
16 f1 04 (Handshake Record header) . . .
b8 79 a1 60 be 6c . . . (ENCRYPTED ServerFinished) . . .
```

On receiving the server public key, the client generates

`secret = ecdh(client_private_key, server_public_key)`

which is used to derive encryption keys. In this case, it generates the following keys using HKDF:

`key_enc, key_dec, iv_enc, iv_dec = HKDF(secret, 56, “handshake key expansion”)`

Note that since each connection uses a different pair of client keys, the shared secret and any derived keys and IVs will be different between connections. The full set of HKDF-derived keys, and what those keys are used for, is illustrated in the [Full key derivation details](#full-key-derivation-details) section.

## Encryption

The details in this section are mostly from dynamically hooking the `Crypt` function in `libwechatnetwork.so` and the OpenSSL routines it calls.

All of the encryption at this layer uses `AES-GCM` with a 128-bit key and a 96-bit nonce. The MMTLS record header and record number are provided as additional authenticated data (or `aad`). Finally, the authentication `tag` from AES-GCM is appended to the end of the ciphertext.

Below is some sample Python code that decodes a Data `record` from the server, given the correct `key` and `iv`.
```
    record_header = record[:5]
    ciphertext = record[5:-16]
    tag = record[-16:]
    aad = bytes.fromhex("0000000000000002") + record[:5]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)
```

### Longlink vs Shortlink

Things differ a bit between Longlink and Shortlink encryption. Since Longlink connections can sustain more than a single round-trip of communication (since it's over TCP), subsequent Longlink `Data` packets are encrypted with a key derived from the shared `secret`. 

Since Shortlink connections can only sustain a single round-trip of communication (since it's encoded into an HTTP POST request), any data sent over Shortlink has to be encrypted as `EarlyData` using the MMTLS equivalent of 0-RTT TLS session resumption. This `EarlyData` key is also derived from the shared `secret`, but in a slightly different way. See [full key derivation details](#full-key-derivation-details).

## Full key derivation details
These details were identified by hooking the `HKDFExtract` and `HKDFExpand` functions running in `libwechatnetwork.so` in the `com.tencent.mm:push` process.

The below are the keys resulting from expanding `secret = ECDH(server_pub, client_priv)` via HKDF, and where these particular keys and IVs are used. The text given, like `handshake key expansion`, are used as HKDF labels. Note that the client keypair between Longlink connections and Shortlink connections are different, so they are expanded from a different shared `secret`.

Finally, note that the associated `iv` is always incremented by 1 each time the associated `key` is used.

### Longlink

 * `handshake key expansion`: 56 bytes, `k_enc k_dec iv_enc iv_dec`
    * `k_dec` and `iv_dec` used to decrypt `ServerHello` encrypted records
    * `k_enc` and `iv_enc` used to encrypt `ClientFinished` handshake record.
 * `expanded secret`: 32 bytes
    * `application data key expansion`: 56 bytes, `k_enc k_dec iv_enc iv_dec`
        * `k_enc iv_enc` used to encrypt the data record in the `ClientFinished` packet, as well as any other data records afterwards sent by client.
        * `k_dec iv_enc` used to decrypt any data records sent by server.
* `PSK_ACCESS`: 32 bytes; Unused for longlink.
* `PSK_REFRESH`: 32 bytes
    * Saved to `psk.key` alongside `resumption_ticket` decrypted from `ServerHello`.
* `server_finished`: 32 bytes
* `client_finished`: 32 bytes

### ShortLink

 * `handshake key expansion`: 56 bytes, `k_enc k_dec iv_enc iv_dec`
    * `k_dec` and `iv_dec` used to decrypt `ServerHello` encrypted records
    * `k_enc` and `iv_enc` used to encrypt `ClientFinished` handshake record.
 * `expanded secret`: 32 bytes
    * `application data key expansion`; Unused for shortlink.
* `PSK_ACCESS`: 32 bytes
    * **Each time a new Shortlink connection is made, HKDF is used to expand a new set of `early_data` and `handshake` keys.**
    * `early data key expansion + hash(handshake)`: 28 bytes, `key iv`
        * Used to encrypt `early_data` in `ClientHello`.
    * `handshake key expansion + hash(handshake)`: 28 bytes, `key iv`
        * Used to decrypt `early_data` response in `ServerHello`

* `PSK_REFRESH`: 32 bytes
    * Saved to `psk.key` alongside `resumption_ticket` decrypted from `ServerHello`.
* `server_finished`: 32 bytes
* `client_finished`: 32 bytes