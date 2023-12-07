from Cryptodome.Cipher import AES
from hashlib import md5
import unittest

"""
These tests are related to the outer layer of AES-GCM in MMTLS encryption.
"""

def hexdump(bytes):
    for i in range(0, len(bytes) // 16):
        for j in range(0, 16):
            print(f'{bytes[i*16+j]:02x} ', end='')
        print()

def bytestring_to_bytes(s):
    return bytes.fromhex(s.replace(' ', ''))

class Tests(unittest.TestCase):
    def test_psk_decryption(self):
        hash = md5(b'Google-sdk_gphone64_arm64').hexdigest()
        key = bytes(hash[0:16], 'utf-8')
        nonce = bytes(hash[0:12], 'utf-8')
        with open("psk.key", "rb") as f:
          ciphertext = f.read()
        plaintext = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt(ciphertext)
        expected_prefix = bytes([0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xa4, 0x02, 0x00, 0x27, 0x8d, 0x00, 0x00, 0x20, 0x52])
        self.assertEqual(plaintext[0:16], expected_prefix)
    
    def test_mmtls_encryption(self):
        '''
        [+] Crypt (mode: ENCRYPT)
        nonce:
                    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
        6dc3e18950  36 ee 03 7a 25 8f bb 83 ca 1f 97 62              6..z%......b

        key:
                    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
        6e33e7aed0  29 b3 7a ff d9 82 38 fb 03 70 c5 64 d8 fa 99 2e  ).z...8..p.d....

        input1:
                    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
        6dc3e19f10  00 00 00 00 00 00 00 01 16 f1 04 00 37           ............7

        input2:
                    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
        6df3e7d4d0  00 00 00 23 14 00 20 09 d6 fc 43 a6 5a 48 dd 64  ...#.. ...C.ZH.d
        6df3e7d4e0  e3 b6 84 65 62 d1 37 52 f5 ab c2 cb 25 45 39 90  ...eb.7R....%E9.
        6df3e7d4f0  6e cd 42 9d f7 10 82                             n.B....

            [+] Crypt output (ENCRYPTED):
                    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
        6e63e52ec0  16 f1 04 00 37 e4 bd ea 65 2c d8 0a 27 3f d2 ef  ....7...e,..'?..
        6e63e52ed0  54 9d f4 c8 7c 10 83 c2 3f 65 8f cc 2d 41 52 d1  T...|...?e..-AR.
        6e63e52ee0  63 bc 80 9f 35 a5 6f d0 f4 a6 2c aa 13 8d 76 5a  c...5.o...,...vZ
        6e63e52ef0  08 6e ec 02 e2 17 04 89 2a 98 1c f7              .n......*...
        '''
        aad = bytes.fromhex('00 00 00 00 00 00 00 01 16 f1 04 00 37')
        key = bytes.fromhex('29b37affd98238fb0370c564d8fa992e')
        nonce = bytes.fromhex('36ee037a258fbb83ca1f9762')
        expected_plaintext = bytestring_to_bytes(''.join([
            '00 00 00 23 14 00 20 09 d6 fc 43 a6 5a 48 dd 64',
            'e3 b6 84 65 62 d1 37 52 f5 ab c2 cb 25 45 39 90',
            '6e cd 42 9d f7 10 82',
        ]))
        expected_ciphertext = bytestring_to_bytes(''.join([
            '16 f1 04 00 37 e4 bd ea 65 2c d8 0a 27 3f d2 ef', # input1
            '54 9d f4 c8 7c 10 83 c2 3f 65 8f cc 2d 41 52 d1', # input2
            '63 bc 80 9f 35 a5 6f d0 f4 a6 2c aa 13 8d 76 5a',
            '08 6e ec 02 e2 17 04 89 2a 98 1c f7',
        ]))

        expected_tag = expected_ciphertext[-16:] # Final 16 bytes are the MAC
        expected_ciphertext = expected_ciphertext[5:-16] # Remove record header and MAC

        # ENCRYPT test
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(expected_plaintext)
        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(tag, expected_tag)

        # DECRYPT test
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        plaintext = cipher.decrypt(expected_ciphertext)
        self.assertEqual(plaintext, expected_plaintext)
        # This will throw an exception if the tag does not verify
        cipher.verify(expected_tag)

if __name__ == '__main__':
    unittest.main()
