## Example of WeChat Encrypted request & response headers

These requests sit between the Inner & outer layers of encryption.


When logged-in, generally the format of an Encrypted WeChat request looks like the following:

```
00 00 00 7b 				(total data length)
00 24						(URI length)
/cgi-bin/micromsg-bin/...		(URI)
00 12						(hostname length)
sgshort.wechat.com			(hostname)
00 00 00 3D				(length of rest of data)
BF B6 5F					(request flags)
41 41 41 41				(user ID)
42 42 42 42				(device ID)
FC 03 48 02 00 00 00 00		(cookie)
1F 9C 4C 24 76 0E 00			(cookie)
D1 05						varint(request_type)
0E 0E 00 02				(4 more varints)
BD 95 80 BF 0D				varint(signature)
FE						(flag)
80 D2 89 91				varint(??)
04 00 00					(marks start of data)
08 A6 29 D1 A4 2A CA F1 ...		(ciphertext)

bf b6 5f					(flags)
41 41 41 41				(user ID)
42 42 42 42				(device ID)
fc 03 48 02 00 00 00 00 		(cookie)
1f 9c 4c 24 76 0e 00 
fb 02						varint(request_type)
35 35 00 02				varints
a9 ad 88 e3 08				varint(signature)
fe
ba da e0 93				varint(??)
04 00 00					(marks start of data)
b6 f8 e9 99 a1 f4 d1 20 . . .	ciphertext
```

### Pseudocode notes

Looking at FUN_0013b270 in `libMMProtocalJni.so` which is largely responsible for serializing the WeChat request header.
```
 OBJECT MEMORY 
 -10                          00 00 00 00 00 00 00 00
      [flags    ] [ uid     ] [ device  ] [ cookie
  00  00 02 05 0f 37 41 42 43 44 41 42 43 44 03 48 02
                                     ] [typ] [1d:
  10  00 00 00 00 14 cd 1e 09 cf 97 00 d1 02 04 00 00
       ] [21:      ] [25:] [27:]    [2a: sig  ] [] [2f...
  20  00 04 00 00 00 00 00 02 00 01 82 07 5a 54 fe 2a
             ] [] []
  30  03 59 42 00 00 00 ee 01 89 80 ad eb 00 00 00 00
  40  f0 b5 52 10 7e 00 00 00 8a 80 ad eb 00 00 00 00
  50  00 00 00 00 00 00 00 00 00 a0 b4 9b 7b 00 00 00

SERIALIZED OBJECT
  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
  bf b6 5f 44 43 42 41 44 43 42 41 bb 03 48 02 00  .._DBCADBCA..H..
  00 00 00 14 cd 1e 09 cf 97 00 d1 05 04 04 00 02  ................
  82 8f e8 a2 05 fe aa 86 e4 92 04 00 00 00 00 00  ................


# WRITE HEADER PSEUDOCODE
# assuming obj is byte*, indices are in hex
  write(0xbf)
  write(compress_flags(obj[0:4]))   # compress flags into 2 bytes
  write(reverse_endian(obj[4:8]))   # writing UID
  write(reverse_endian(obj[8:c]))   # writing device ID
  write(obj[12:1b])                 # cookie
  write(varint(obj[1b:1d]))         # request type
  write(varint(obj[1d:21]))         # fn 13a56c
  write(varint(obj[21:25]))         # fn 13a5a4
  write(varint(obj[25:27]))         # serialized param_9
  write(varint(obj[27:29]))         # 
  write(varint(obj[2a:2d]))         # signature
  write(obj[2e])                    # 
  write(obj[2f:33])                 #
  write(obj[33])
  write(obj[34])
  ```