# Reversing notes and other scratch
Notes from reversing. Not very organized, but could be helpful?

## libwechatmm.so call logs
### logged-out; all requests
Before request:
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_CreateHybridEcdhCryptoEngine called
libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_HybridEcdhEncrypt called
    * Generate Client EC public key, Client EC private key for client
    * Generate EC key 1 using Server EC Public Key, Client EC private key
    * AES-GCM Encrypt using EC key 1
    * Client EC public key sent alongside ciphertext
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_packHybridEcdh called
    * packHybridEcdh only does packing but no encryption

On receiving response:
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_unpack called
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_HybridEcdhDecrypt called
    * AES-GCM Decrypt using EC key 1
    * Verify server response with ECDSA public key
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_ReleaseHybridEcdhCryptoEngine called

### logged in: first request

Before sending request:
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_ecdsaGeneralOctKeyPair called
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_generateECKey called
    * Generate EC public key, Client EC private key for client
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_CreateHybridEcdhCryptoEngine called
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_HybridEcdhEncrypt called
    * Generate EC key using Diffie-Hellman with Server ECDH Public Key, Client EC * private key
    * Encrypt (AES-GCM) using EC key
    * EC public key sent alongside data
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_packHybridEcdh called

On receiving response:
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_unpack called
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_HybridEcdhDecrypt called
    * Decrypt (AES-GCM) using EC key
    * Server has generated new Server EC Public Key
    * Verify server response with ECDSA public key
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_ReleaseHybridEcdhCryptoEngine called
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_computerKeyWithAllStr called
    * Generate new EC key using DH with Server EC Public Key, EC private key
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_aesDecrypt called
    * Decrypt (AES-CBC) symmetric session key using new EC key

### logged-in: Default encryption after initial request
Request:
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_genSignature
    * "MAC" using new EC key
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_pack
    * Encrypt (AES-CBC) using session key

Response:
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_unpack
    * Decrypt (AES-CBC) using session key

### logged-in: some other requests
Example: /newsync URI
Request:
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_genSignature
    * MAC using new EC key
* libwechatmm.so:Java_com_tencent_mm_jni_utils_UtilsJni_AesGcmEncryptWithCompress
    * Encrypt (AES-GCM) using client_session
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_pack

Response:
* libMMProtocalJni.so:Java_com_tencent_mm_protocal_MMProtocalJni_unpack

## Pseudocode: libMMProtocalJNI.so [AES-CBC path]
### genSignature
```
genSignature (uin, ecdh_key, buff, buff_len)
// libMMProtocalJni.so:0x0013e620
// this function is effectively used as a “MAC” to check for message tampering
// all md5_* functions seem like they are compiled from openSSL
  buff96 [96];
  buff92 [92];
  buff28 [28];

  md5_init(buff92);
  uin = change_endianness(uin);
  md5_update(buff92, &uin, 4)

  md5_update(buff92, ecdh_key, ecdh_key_len)
  md5_final(buff28, buff92)

  md5_init(buff96)
  buff_len = change_endianness(buff_len)

  md5_update(buff96, buff_len, 4)

  md5_update(buff96, ecdh_key, ecdh_key_len)
  md5_update(buff96, buff28, 0x10)

  md5_final(buff28, buff96)

  adler = adler32(0,0,0)
  adler = adler32(adler, buff28, 0x10)
  return adler32(adler, buff, bufflen)
```
### AesEncrypt (CBC)
```
// note: user_key == iv; caller says
//   FUN_0013d108_aes_encrypt
//      (user_key,user_key_len,user_key,user_key_len,data,data_len,out_ptr,outlen_ptr)
// libMMProtocalJni.so:0x0013d108
aes_encrypt:
  void* user_key, uint user_key_len
  void* iv, uint iv_len
  void* data, uint data_len
  void** out_ptr, uint* out_len_ptr

	aes_key_buff [248]
	ivec_buff [16]
	user_key_buff [16]

	if iv_len > 15:
    	iv_len = 16

	iv_padding = 0
	if (iv_len < 16):
    	iv_padding = 16 - iv_len
	memset(ivbuff + iv_len, 0, iv_padding)
	memcpy(ivbuff, iv, iv_len)

	if user_key_len > 15:
    		user_key_len = 16
	memcpy(user_key_buff, user_key, user_key_len)
	AES_set_encrypt_key(user_key_buff, 0x80, aes_key_buff)

	padding = 16 - (data_len & 0xf)
	padded_len = padding + data_len

	databuff = malloc(padded_len)
	memcpy(databuff, data, data_len)
	memset(databuff + data_len, padding, padding) // PKCS7 padding
	*out_len_ptr = padded_len
	*outbuff = malloc(padded_len)
	memset(outbuff, 0, padded_len)

	AES_cbc_encrypt(databuff, outbuff, paddedlen, aes_key_buff, iv_buff, 1)
```

## pack() notes
libMMProtocalJni.so “pack” functions
pack
* mmpack.cpp:EncodePack 
    * encrypt_flag (param15), ext_flag (param21) 
    * if ecrypt_flag == 0xd  (“AES_GCM_ENCRYPT”)
        * fn_packdata2
    * else (“NO_ENCRYPT”)
        * mmpack.cpp:EncryptPack
            * rbCompressedBuf, keypem, keyn, keye, encrypt=5
            * if not has aes_key:
                * if has keypem:
                    * rsa_crypt.cpp:rsa_public_encrypt_pemkey
                        * Extracts public key params from PEM encoded key * rsa_encrypt
                * else:
                    * rsa_encrypt(keyn, keye)
            * elif (encrypt == 5) (this is always true):
                * _encryptAES
            * elif (encrypt ==3)
                * _encryptDES
packHybrid
* mmpack.cpp:EncodeHybridEncryptPack
    * iCoreCrypt.cpp:HybridEncrypt
        * compress and encrypt with RSA and AES. AES key store in RSA plain data
packDoubleHybrid
* mmpack.cpp:EncodeDoubleHybridEncryptPack
    * iCoreCrypt.cpp:DoubleHybridEncrypt
        * compress and encrypt with RSA and AES. AES key store in RSA plain data
        * rsa buffer will encrypt twice with rsa and aes key.
packHybridEcdh
* mmpack.cpp:EncodeHybridEcdhEncryptPack
    * Fn_packdata
unpack
* if flag = -0x133 (some internal status code)
    * rsa_crypt.c:rsa_public_decrypt
        * client key hard-coded
* else
    * mmpack.cpp:DecryptPack
        * If crypt_algorithm == 10
            * Rsa_crypt.c:rsa_public_decrypt
        * If crypt_algorithm == 5
            * _AESdecrypt
        * else
            * _DESdecrypt
genSignature
* calls out to checksumming algorithm, using adler32
* by “signature” i think they mean checksum

## libwechatmm.so pseudocode
```
crypto_engine object:
  p0: int state = 0 at start
  p01: int nid (type of curve, passed to EC_KEY_new_by_curve_name)
  p02: ecdhkey data
  p04: ecdhkey data
  p06: ecdhkey data
  p08: ecdsakey data
  p0c: ecdsakey data
  p10: ecdsakey data
  p12: autoauth key
  p14: privkey_buff

(+ others...)
```
note: uses openSSL bindings
```

CreateCryptoEngine (int nid, byte[] ecdh_key, byte[] ecdsa_key, byte[] autoauth_key)
  allocate memory for crypto_engine
  for both ecdh key and ecdsa key:
	copies keydata crypto_engine object
  if has autoauthkey
	HybridEcdhClientWithAAKey(cryptoengine_ptr, nid, blocksize1, blocksize2, 
&autoauthkey)
  else
	HybridEcdhClientWithoutAAKey(cryptoengine_ptr, nid, blocksize1, blocksize2)

ECDHEncrypt (void* crypto_engine, char* plaintext, long plaintext_len, void* response_ptr)
 GenEcdhKeyPair(void* lock, int nid, void* response_ptr, [crypto_engine + 0x14])
  ec_key = EC_KEY_new_by_curve_name(nid)
  EC_KEY_generate_key(ec_key)
  pubkey_len = i2o_ECPublicKey(ec_key, &pubkey_out)
  privkey_len = i2d_ECPrivateKey(ec_key, &privkey_out)
  move_buffer_into(response_ptr, pubkey_buffer, pubkey_len)
  move_buffer_into([cryptoengine + 0x14], privkey_buffer, privkey_len)
 ECDHWrapper(lock, nid, ecdh_key?, private_key, &pointer)
  ECDH(lock, nid, ecdh, ecdh_len, privkey, privkey_len, outpointer)
   ec_pub = EC_KEY_new_by_curve_name(nid)
   ec_pub = o2i_ECPublickey(ec_pub, ecdh, ecdh_len)
   ec_priv = EC_KEY_new_by_curvename(nid)
   ec_priv = d2i_ECPrivateKey(ec_priv, privkey, privkey_len)
   // a bunch of arithmatec with outpointer param
   out = outptr + 8
   ECDH_compute_key(out, 0x20 (outlen), ec_pub+20(ec_point), ec_priv, kdf_callback_fn) 
 ctx = SHA256_init()
 SHA256_update(ctx, "00...001" (len 0x40))
 SHA256_update(ctx, nid (len 0x40))
 SHA256_update(ctx, pubkey)
 SHA256_final(ctx, pubkey)

 gen_random(0x20, rand_buff)
 WrapAesGcmEncryptWithCompress(ecdh_out, sha256_hash, rand_buff, encrypt_out)
 doHkdf(lock, ??, rand_buff, sha2526_hash, outptr, outlen)

 // another set of sha256 hashes; TODO what exactly are they hashing?
 AesGcmWithCompress(hkdffed_key, key_len, new_sha, new_sha_len, plaintext, plaintext_len, outbuff2)
 return;

// new function def
WrapAesGcmEncryptWithCompress(ecdh_out, sha256_hash, data, encrypt_out)
   key, key_len from ecdh_out
   aad, aad_len from sha256_hash
   plaintext, plaintext_len from data
   AesGcmEncryptWithCompress(key, key_len, aad, aad_len, plaintext, plaintext_len, outbuff)
	ZlibCompress(plaintext, plaintext_len, &compressed, &compressed_len)
	WrapAesGcmEncrypt(key, evp_cipher, aad, aad_len, compressed, compressed_len, outbuff)
 	AesGcmEncrypt:
   		(lock, iv, iv_len, key, evp_cipher, aad, aadlen, compressed, compressed_len, outbuff, tag, tag_len)
 	append iv to outbuff
 	append tag to outbuff

AesGcmEncrypt(lock, iv, iv_len, key, evp_cipher, aad, aadlen, compressed, compressed_len, outbuff, tag, tag_len)
  ctx = EVP_CIPHER_CTX_new()
  EVP_CipherInit_wrapper(ctx, ctx, evp_cipher)
  // sets IV length
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, 9, iv_len, 0)
  EVP_EncryptInit_ex(ctx, 0, 0, key, iv)
  EVP_EncryptUpdate(ctx, 0, &out_len, aad, aadlen)
  EVP_EncryptUpdate(ctx, &outbuff, &out_len, plaintext, plaintext_len)
  EVP_EncryptFinal_ex(ctx, &outbuf + out_len, &out_len)
  // reads final tag into “tag” buffer
  EVP_CIPHER_CTX_ctrl(ctx, 0x10, taglen, tag)
  EVP_CIPHER_CTX_free(ctx)
  ```

## static public keys pinned
In com.tencent.mm.protocal.f (can search through for string "getHybridEcdhCryptoEngine" which is included in some logging output) we have `afSr`/`afSs` which are clearly pinned public keys for the server. they're also passed to CreateHybridEcdhCryptoEngine. here they are decoded with openSSL
```
BI2xbGdfzrMI1qWI8Yatcqv5Z1vFLwtLdm1DkHGEUh6ZzRqDMMVeQ4Xxy+YxgR8D/KPo6hGx5iaDKtdQs5XaeEE=

00000000: 048d b16c 675f ceb3 08d6 a588 f186 ad72  ...lg_.........r
00000010: abf9 675b c52f 0b4b 766d 4390 7184 521e  ..g[./.KvmC.q.R.
00000020: 99cd 1a83 30c5 5e43 85f1 cbe6 3181 1f03  ....0.^C....1...
00000030: fca3 e8ea 11b1 e626 832a d750 b395 da78  .......&.*.P...x
00000040: 41

EC key

LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFYmJLaC9KRGJxbnpLNWFPRzQ4cnF0YnlmQ2g5dAorMlNWZ3RsTGpUU2FwemFxUGlpY2RQUkVHSmM4L2xDaHUxU2cxa1hIcTRyNW1ieFpMcUxVVUhTODl3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==

Public-Key: (256 bit)
pub:
    04:6d:b2:a1:fc:90:db:aa:7c:ca:e5:a3:86:e3:ca:
    ea:b5:bc:9f:0a:1f:6d:fb:64:95:82:d9:4b:8d:34:
    9a:a7:36:aa:3e:28:9c:74:f4:44:18:97:3c:fe:50:
    a1:bb:54:a0:d6:45:c7:ab:8a:f9:99:bc:59:2e:a2:
    d4:50:74:bc:f7
ASN1 OID: prime256v1
```
We hook into a function that wraps OpenSSL’s o2i_ECPublicKey, which is a function that takes a serialized 65-length bytearray and turns it into a EC_KEY object.
o2i_ECPublicKey is called twice per call to the HybridEcdhEncrypt JNI. Each time, the two keys given to this function are consistent:
```
[!] called o2i public key
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
766d6c41d0  04 8d b1 6c 67 5f ce b3 08 d6 a5 88 f1 86 ad 72  ...lg_.........r
766d6c41e0  ab f9 67 5b c5 2f 0b 4b 76 6d 43 90 71 84 52 1e  ..g[./.KvmC.q.R.
766d6c41f0  99 cd 1a 83 30 c5 5e 43 85 f1 cb e6 31 81 1f 03  ....0.^C....1...
766d6c4200  fc a3 e8 ea 11 b1 e6 26 83 2a d7 50 b3 95 da 78  .......&.*.P...x
766d6c4210  41                                               A
[!] called o2i public key
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
766d6c4950  04 6d b2 a1 fc 90 db aa 7c ca e5 a3 86 e3 ca ea  .m......|.......
766d6c4960  b5 bc 9f 0a 1f 6d fb 64 95 82 d9 4b 8d 34 9a a7  .....m.d...K.4..
766d6c4970  36 aa 3e 28 9c 74 f4 44 18 97 3c fe 50 a1 bb 54  6.>(.t.D..<.P..T
766d6c4980  a0 d6 45 c7 ab 8a f9 99 bc 59 2e a2 d4 50 74 bc  ..E......Y...Pt.
766d6c4990  f7   
```

