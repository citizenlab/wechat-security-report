import unittest

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

class Tests(unittest.TestCase):
    def test_pack_aescbc_encryption(self):
        """ Encryption as it is done in pack() in libMMProtocalJni.so.
        """
        key = bytes.fromhex("75 58 64 38 68 73 76 7b 6b 7d 23 45 74 76 55 67")
        # Uses same IV as key.
        iv = key
        data = "0a 02 08 3a"

        expected_ciphertext = "52 a2 a9 5b cc c4 d3 58 ec ad 2e 75 14 90 c4 f6"
        data = bytes.fromhex(data)

        cipher = AES.new(iv, AES.MODE_CBC, iv=iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        self.assertEqual(bytes.fromhex(expected_ciphertext), ct_bytes)

    def test_unpack_aescbc_decryption(self):
        """ Decryption as it is done in unpack() in libMMProtocalJni.so.
        """
        key = bytes.fromhex("41 65 63 58 27 6f 64 29 74 2f 65 70 4b 7d 39 23")
        iv = key
        ciphertext = "85 66 1f 20 83 72 c8 8d bb 28 d3 be 4d 47 a1 1b"
        ciphertext = bytes.fromhex(ciphertext)
        expected_plaintext = "0a 06 08 00 12 02 0a 00 12 02 08 67"

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
        self.assertEqual(bytes.fromhex(expected_plaintext), pt_bytes)

    def test_hybriddecrypt_aesgcm(self):
        """ These two ciphertexts should decrypt to the same plaintext, and pass
        AES-GCM tag verification.
        """
        ciphertext1 = bytes.fromhex("""
        0b 02 e7 6a 53 cd fb c1 43 c0 7c b7 5f 79 d7 cb 
        67 c4 8e 2a 94 6b 14 aa 15 b5 a7 25 43 da f9 d7 
        7b 40 e7 d8 ee b7 55 37 77 cd aa 3a e7 4a 22 a9 
        8d 1f b1 6b ef bd c0 47 1d 79 77 74 18 47 92 41
        79 a3 87 70 8c""")
# {"layer":"INNER","encrypt":true,"key":"7b5a045393a9d3646a5100d2b837e0507720fe20ca8550aa","iv":"cdaa3ae74a22a98d1fb16bef","metadata":"795a4e8a02ca77f8bb2dd78ece118b56d6598740c8d59a3d652f3fd2902e6e19","tail":"cdaa3ae74a22a98d1fb16bef","tag":"bdc0471d7977741847924179a387708c"}

        key1 = bytes.fromhex("7b5a045393a9d3646a5100d2b837e0507720fe20ca8550aa")
        tag1 = ciphertext1[-16:]
        iv1 = ciphertext1[-16-12:-16]
        aad = bytes.fromhex("795a4e8a02ca77f8bb2dd78ece118b56d6598740c8d59a3d652f3fd2902e6e19")

        cipher = AES.new(key1, AES.MODE_GCM, nonce=iv1)
        cipher.update(aad)
        plaintext1 = cipher.decrypt(ciphertext1[:-16-12])
        cipher.verify(tag1)

        ciphertext2 = bytes.fromhex("""
        3a 7f a7 89 3f cd f4 a5 d1 15 a2 1c 83 55 0a 10 
        34 11 40 07 ef 6b 11 c8 b1 23 b9 a9 d5 79 3e 6c 
        5c 8c 75 1f 13 96 ab 66 c5 dc 5f f0 ad be 3e c1 
        cc 10 c4 6e c8 a5 74 3c ea b5 b8 ee e2 3c 7b 98 
        a1 37 fb 6c eb""")
# {"layer":"INNER","encrypt":true,"key":"64cbe696f9a7059dfd415c949c932435727059e6a790aaec","iv":"dc5ff0adbe3ec1cc10c46ec8","metadata":"795a4e8a02ca77f8bb2dd78ece118b56d6598740c8d59a3d652f3fd2902e6e19","tail":"dc5ff0adbe3ec1cc10c46ec8","tag":"a5743ceab5b8eee23c7b98a137fb6ceb"}

        key2 = bytes.fromhex("64cbe696f9a7059dfd415c949c932435727059e6a790aaec")
        tag2 = ciphertext2[-16:]
        iv2 = ciphertext2[-16-12:-16]

        cipher = AES.new(key2, AES.MODE_GCM, nonce=iv2)
        cipher.update(aad)
        plaintext2 = cipher.decrypt(ciphertext2[:-16-12])
        cipher.verify(tag2)

        self.assertEqual(plaintext1, plaintext2)

if __name__ == '__main__':
    unittest.main()
