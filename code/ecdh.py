from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from util import hexdump
from hashlib import sha256
import unittest

"""
This tests generating a secret for ECDH.
This applies both to the handshakes for the outer MMTLS layer as well as the inner layer.
"""

# SHA256(ECDH(server_pub, client_prv))
def wechat_ecdh_gen_key(server_pub_oct: bytes, client_prv_der: bytes) -> bytes:
    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub_oct)
    client_prv = serialization.load_der_private_key(client_prv_der, None)
    shared = client_prv.exchange(ec.ECDH(), server_pub)
    return sha256(shared).digest()

def str2bytes(s: str) -> bytes:
    return bytes.fromhex(s.replace(' ', '').replace('\n', ''))

class Tests(unittest.TestCase):

    def test_str2bytes(self):
        pub = str2bytes('''
        04 ba 02 29 0f f2 9b fb ac 78 6f 0f ec 38 c9 bf
        a2 0a ae 9a 8e a8 a7 e2 f6 b2 4d 0c ab 34 84 12
        dd 51 ed 35 46 8f 78 71 c0 6a 27 9f f5 32 24 d6
        1e d1 69 7d 02 45 7b c2 a2 90 ff cc 75 35 ad 26
        af                                             
        ''')
        self.assertEqual(pub[0:8], b'\x04\xba\x02\x29\x0f\xf2\x9b\xfb')
        self.assertEqual(len(pub), 65)
    
    def test_pubkey_stuff(self):
        prv_der = str2bytes('''
        30 77 02 01 01 04 20 0b 81 dc 0a 73 66 6e 6e fc
        a2 a4 30 5d 6b 84 3f 60 b7 ef 97 cf 75 5e 19 ba
        2e 9b 45 cb 58 0d b2 a0 0a 06 08 2a 86 48 ce 3d
        03 01 07 a1 44 03 42 00 04 14 b5 34 31 92 71 93
        76 2d 37 d9 b7 35 5d 7f 51 a3 8d 63 7d 31 bd ca
        4b 63 fd 79 58 b0 ce 8a d2 fe d5 1e 92 69 aa 5e
        72 a6 a0 50 4d 2b 63 68 fc 5e f3 e1 3c 77 cc 82
        a9 4f 06 49 80 5f ec dc 7d                     
        ''')
        client_prv = serialization.load_der_private_key(prv_der, None)
        client_pub = client_prv.public_key()
        print('client pub:')
        hexdump(client_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    
    def test_ecdh(self):
        pub = str2bytes('''
        04 ba 02 29 0f f2 9b fb ac 78 6f 0f ec 38 c9 bf
        a2 0a ae 9a 8e a8 a7 e2 f6 b2 4d 0c ab 34 84 12
        dd 51 ed 35 46 8f 78 71 c0 6a 27 9f f5 32 24 d6
        1e d1 69 7d 02 45 7b c2 a2 90 ff cc 75 35 ad 26
        af                                             
        ''')

        prv = str2bytes('''
        30 77 02 01 01 04 20 0b 81 dc 0a 73 66 6e 6e fc
        a2 a4 30 5d 6b 84 3f 60 b7 ef 97 cf 75 5e 19 ba
        2e 9b 45 cb 58 0d b2 a0 0a 06 08 2a 86 48 ce 3d
        03 01 07 a1 44 03 42 00 04 14 b5 34 31 92 71 93
        76 2d 37 d9 b7 35 5d 7f 51 a3 8d 63 7d 31 bd ca
        4b 63 fd 79 58 b0 ce 8a d2 fe d5 1e 92 69 aa 5e
        72 a6 a0 50 4d 2b 63 68 fc 5e f3 e1 3c 77 cc 82
        a9 4f 06 49 80 5f ec dc 7d                     
        ''')

        expected_key = str2bytes('''
        90 ed 53 f8 d2 7f 4e d5 66 de 42 2e 68 35 f8 bc
        6c 5a c5 60 d2 ca 36 5d 44 5d 62 8f d0 76 76 31
        ''')
        self.assertEqual(wechat_ecdh_gen_key(pub, prv), expected_key)

if __name__ == '__main__':
    unittest.main()
