* Generally, the requests on the wire are using various encryption systems that comprise the “inner encryption” layer of our current protocol. For the headers, we’ve identified (A) encryption flags and (B) various varint-encoded data that correspond to relevant metadata, such as the requestType.
* From dynamic + static analysis of the app when logged out, there are yet even more confusing cryptosystems. In the current day, the “inner encryption” layer is basically static ECDH. In 2016 version, we observed these two occurring:
  * RSA_encrypt(data=aes_key, key=static_pubkey) || AES_encrypt(data=plaintext, key=aes_key)
  * DES with a known key (observed, traced via dynamic analysis)
    * Seems to be used only for stack reports on crashes and sending WeChat message metadata (NetSceneDirectSend)
* From static analysis of the app when logged in, encryption occurs /mostly/ within MMProtocalJni.pack using a fixed “sessionKey”, which matches the behavior we observe in 2023 for the “inner encryption” layer.
* Generally, the structure of how requests are handled is still basically the same as in our current analysis.

A few requests made consistently on startup:
```
GET cgi-bin/micromsg-bin/newgetdns
/cgi-bin/micromsg-bin/newgetdns?uin=0&clientversion=637734961&scene=0&net=2&md5=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&devicetype=android-16&lan=en&sigver=2
```
* Resolves short/long hostnames specific to wechat

```
POST cgi-bin/micromsg-bin/getkvidkeystrategyrsa
```
* Sent on startup each time; request-type: 722
* reqToBuf for MMEncryptCheckResUpdate
* Encrypted using packHybrid

On crashes:
```
POST /cgi-bin/mmsupport-bin/stackreport?version=26031031&devicetype=android-16&filelength=11418&sum=e915aedd7514f2d52f280df658233496&reporttype=1&NewReportType=10001&username=never_login_crash
```
* Encrypted using DES

### Dynamic analysis notes
com.tencent.mm
```
Java_com_tencent_mm_protocal_MMProtocalJni_packHybrid()
Java_com_tencent_mm_protocal_MMProtocalJni_unpack()
```
```
Java_com_tencent_mm_protocal_MMProtocalJni_packHybrid
-> calls protocal_packHybrid
undefined4
FUN_0002e5a8_protocal_packHybrid
(output, cookie_, hardwaredata, uin, functype, rsaversion,
        	 rsa_data, aes_data, keye, keyn,
        	 aeskey_passkey, isforeground)

-> calls EncodeHybridEncryptPack
void FUN_0002391c_EncodeHybridEncryptPack
           	(output, cookie, uin, hardwaredata, func,rsa_version, rsaInput, aesInput, rsakeye, rsakeyn, aes_key, isforeground)

-> calls iCoreCrypt::HybridEncrypt (headers are public)
```

