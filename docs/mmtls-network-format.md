
ClientHello (1-RTT ECDSA) - Longlink or Shortlink
```
16 f1 04			HANDSHAKE HEADER
01 6e				record length (bytes)
00 00 01 6a			section length
01 03 f1			ClientHello constant
02					num ciphersuites
c0 2b               ECDHE_ECDSA_AES_128_GCM_SHA256
00 a8               PSK_WITH_AES_128_GCM_SHA256
				
<32 bytes>			ClientRandom
<4 bytes>			Client timestamp

00 00 01 3a			extension section length
02					number of extensions
00 00 00 8b			extension data length
00 0f 01            PSK extension header
00 00 00 84         ticket section length
02                  ticket index
00 27 8d 00         ticket lifetime hint
00 00               ticket time add
00 00 00 48
00 0c               ticket nonce length
<12 bytes>          ticket nonce
00 69               ticket length
<PSK TICKET>        ticket

00 00 00 a6         extension section length
00 10 02			ECDSA extension header
00 00 00 47	        key section length
00 00 00 01			key index
00 41		        keydata length
<65 bytes>	        client_public1
00 00 00 47		    key section length
00 00 00 02		    key index
00 41		        keydata length
<65 bytes keydata>	client_public2
```
### ServerHello (1-RTT ECDSA)
```
16 f1 04				HANDSHAKE HEADER
00 d4					record length (bytes)
00 00 00 d0			    section length
02 03 f1				ServerHello constant
C0 2b 				    ciphersuite
<32 bytes>				ServerRandom

00 00 00 4e			    extension section length
02					    number of extensions
00 00 00 49 		    extension data length
00 11				    key share extension header
00 00 00 01		 	    key index
00 41 				    keydata length
<65 bytes keydata>		server_public

00 00 00 0a             extension data length
00 13                   extension header
00 00 00 01 00 00 00 03

16 f1 04				HANDSHAKE HEADER
00 5e					record length (bytes)
<data>				    encrypted certificate

16 f1 04                HANDSHAKE HEADER
01 25 				    record length (bytes)
<data>				    Encrypted session ticket

16 f1 04				HANDSHAKE HEADER
00 37					record length (bytes)
<data>                  ServerFinish (aka verify_data)
```

ClientHello (0-RTT)
```

19 f1 04			HANDSHAKE HEADER
00 a1				record length (bytes)
00 00 00 9d			section length
01 03 f1			ClientHello constant
01					num ciphersuites
00 a8				PSK
<32 bytes>			ClientRandom
5f ?? ?? ??			Client timestamp

00 00 00 6f			extension section length
01					number of extensions
00 00 00 6a			extension data length
00 0f 01			PSK extension header
00 00 00 63			ticket section length
01					ticket index
00 09 3a 80			ticket life hint
00 00				ticket time add
00 00 00 3d			
00 0c				nonce length
<12 bytes>			nonce
00 48				PSK/ticket length
<72 bytes>			PSK/ticket

19 f1 04			HANDSHAKE HEADER
00 24				length
<36 bytes>          <encrypted extensions>

17 f1 04			DATA HEADER
00 c9				length
<data>              <encrypted earlydata>

15 f1 04			ALERT HEADER (end data)
00 17				length
<data>              <encrypted end of record>
```

## ServerHello (0-RTT)
```
16 f1 04			HANDSHAKE HEADER
00 d4				record length (bytes)

00 00 00 d0			section length
02 03 f1			ServerHello constant
00 a8				ciphersuite
<32 bytes>			ServerRandom

00 00 00 01			extension section length
00					number of extensions

16 f1 04			HANDSHAKE HEADER
00 37				length
<data>              <encrypted certificate>

17 f1 04			DATA HEADER
01 57
<data>              <encrypted response data>

15 f1 04			ALERT HEADER (end data)
00 17				length
<data>
```