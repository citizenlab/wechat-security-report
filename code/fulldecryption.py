from Cryptodome.Cipher import AES
import unittest
import zlib
from hexdump import hexdump

"""
A single full decryption test for (A) double-AES-GCM and (B) CBC-then-GCM.
"""

AUTOAUTH_REQUEST = "../data/autoauth-request-packet.hex"
AUTOAUTH_RESPONSE = "../data/autoauth-response-packet.hex"

MMTLS_MAGICBYTES = b"\xf1\x04"
def MMTLSRecords(payload):
    while MMTLS_MAGICBYTES in payload:
        record_start = payload.find(MMTLS_MAGICBYTES) - 1
        record_len = int.from_bytes(payload[record_start+3:record_start+5], "big") + 5
        yield payload[record_start:record_start + record_len]
        payload = payload[record_start + record_len:]

KEY_MARKER = b"\x12\x41\x04"

class Tests(unittest.TestCase):
    def _test_decrypt_outer(self, record, key, iv, aad):
        """ Record format:
        [RECORD HEADER] - 3 bytes
        [RECORD LENGTH] - 2 bytes
        [CIPHERTEXT]
        [MAC]           - 16 bytes
        
        RECORD LENGTH is length of CIPHERTEXT + length of MAC.
        """
        cipher = AES.new(bytes.fromhex(key), AES.MODE_GCM, nonce=bytes.fromhex(iv))
        # This below metadata takes the format of:
        #     [00 00 00 00 00 00 00 01]  [16 f1 04]                [00 5e]
        #     [RECORD NUMBER (8 bytes)]  [RECORD HEADER (3 bytes)] [RECORD LENGTH (2 bytes)]
        # This is provided as AAD to AES-GCM.
        cipher.update(bytes.fromhex(aad))
        # Remove record header and MAC.
        ciphertext = record[5:-16] 
        # Retrieve MAC.
        tag = record[-16:]
        plaintext = cipher.decrypt(ciphertext)
        # This will throw an exception if the MAC doesn't verify.
        cipher.verify(tag)
        return plaintext


    def _decrypt_gcm_inner(self, ciphertext, tag, key, iv, aad, request=True):
        start = ciphertext.find(KEY_MARKER) + 1
        if ciphertext.endswith(b"\x22\x00"):
          ciphertext = ciphertext[:-2]
        start += ciphertext[start] + 2 # skip first record; public key
        if request:
            start += ciphertext[start] + 2 # skip second record; first encrypted random data
            start += ciphertext[start] # skip third record; second encrypted random data
        # the rest should be the final, meatiest record
        start += 4
        hexdump(ciphertext[start-16:])
        self.assertEqual(ciphertext[-16:], tag)
        self.assertEqual(ciphertext[-16-12:-16], iv)
        ciphertext = ciphertext[start:-12-16] # remove IV and tag

        cipher = AES.new(key,  mode=AES.MODE_GCM, nonce=iv)
        cipher.update(aad)
        compressed = cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return compressed

    def test_autoauth_request_decryption(self):
        with open(AUTOAUTH_REQUEST) as f:
            data = bytes.fromhex(f.read())
        records = list(MMTLSRecords(data))
        self.assertEqual(len(records), 4)
        self.assertEqual(records[0][0], 0x19) # HANDSHAKE HEADER
        self.assertEqual(records[1][0], 0x19) # ENCRYPTED EXTENSIONS
        self.assertEqual(records[2][0], 0x17) # ENCRYPTED EARLYDATA
        self.assertEqual(records[3][0], 0x15) # ENCRYPTED ALERT

        # OUTER LAYER DECRYPTION
        key = 'c1651ba9cc6f3d03096e4d580b273ace'
        nonce = '104fd3c6fa2d43465caa12d'
        # These non-data records generally don't contain double-encrypted data.
        # Nonces are subtly different.
        self._test_decrypt_outer(records[1], key, nonce + "3", '000000000000000119f1040024')
        self._test_decrypt_outer(records[3], key, nonce + "1", '000000000000000315f1040017')

        # This one is double encrypted.
        outer_plaintext = self._test_decrypt_outer(records[2], key, nonce + "0", '000000000000000217f1041558')
#{'layer': 'INNER', 'encrypt': True, 'key': 'e042f2d14eadda719c28d01340c9155d7c603fe21f34fe26', 'iv': '17bd1750b6dfe633405d91d5', 'metadata': 'b43e292b6cd1d6a05b28a10e552b23fe24fa8811f5d8751b397b1a166b6bddc5', 'tail': '3f428b148b1f268b', 'tag': '0ab9c554f66d68d93f428b148b1f268b'}
        compressed = self._decrypt_gcm_inner(outer_plaintext,
            bytes.fromhex('0ab9c554f66d68d93f428b148b1f268b'),
            bytes.fromhex('e042f2d14eadda719c28d01340c9155d7c603fe21f34fe26'),
            bytes.fromhex('17bd1750b6dfe633405d91d5'),
            bytes.fromhex('b43e292b6cd1d6a05b28a10e552b23fe24fa8811f5d8751b397b1a166b6bddc5'))
        plaintext = zlib.decompress(compressed)
        # hexdump(plaintext)
        self.assertTrue(b"com.tencent.mm" in plaintext)

    def test_autoauth_response_decryption(self):
        with open(AUTOAUTH_RESPONSE) as f:
            data = bytes.fromhex(f.read())
        records = list(MMTLSRecords(data))
        self.assertEqual(len(records), 4)
        self.assertEqual(records[0][0], 0x16) # HANDSHAKE HEADER
        self.assertEqual(records[1][0], 0x16) # ENCRYPTED EXTENSIONS
        self.assertEqual(records[2][0], 0x17) # ENCRYPTED EARLYDATA
        self.assertEqual(records[3][0], 0x15) # ENCRYPTED ALERT

        # OUTER LAYER DECRYPTION
        key = 'd2eb40cb4e05d7a653664b3eea6e6bb0'
        nonce = '72d7b98feaf8427bbff9611'
        # These non-data records generally don't contain double-encrypted data.
        # Nonces are subtly different.
        self._test_decrypt_outer(records[1], key, nonce + "9", '000000000000000116f1040037')
        self._test_decrypt_outer(records[3], key, nonce + "b", '000000000000000315f1040017')

        # This one is double encrypted.
        outer_plaintext = self._test_decrypt_outer(records[2], key, nonce + "a", '000000000000000217f104105a')
#{'layer': 'INNER', 'encrypt': False, 'key': 'e36c67e8313290bcf72ec6c39a1438bb12d0f5fe3023f45c', 'iv': '9977ac15889d21bb0893dd99', 'metadata': 'b8f173607e77387ec324a4e1a1d3b03857a203f18255b3488688d95d30582944', 'tail': '11269876c0884bc7', 'tag': 'd20128c7bacedefe11269876c0884bc7'}
        compressed = self._decrypt_gcm_inner(outer_plaintext,
            bytes.fromhex('d20128c7bacedefe11269876c0884bc7'),
            bytes.fromhex('e36c67e8313290bcf72ec6c39a1438bb12d0f5fe3023f45c'),
            bytes.fromhex('9977ac15889d21bb0893dd99'),
            bytes.fromhex('b8f173607e77387ec324a4e1a1d3b03857a203f18255b3488688d95d30582944'),
            request=False)
        plaintext = zlib.decompress(compressed)
        # hexdump(plaintext)
        self.assertTrue(b"sgshort.wechat.com" in plaintext)



if __name__ == '__main__':
    unittest.main()
