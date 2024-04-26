""" Processing Frida logfile to DL all keys from JSONL format and decrypt netcap.

Outputs JSONL data containing decrypted plaintexts and associated request metadata.

Usage: python decrypt-keylog.py [keylog-json] [netcap-file]

Each JSON object looks like:
{
  "layer": "OUTER",    // INNER or OUTER
    "encrypt": true,     // Was the client encrypting or decrypting?
                         //   i.e. was the packet outgoing or incoming
    "nonce": string,     // Nonce/IV
    "key": string,       // Encryption key
    "tail": string,      // Last 8 bytes of ciphertext
    "metadata": string,  // Any extra data that might
    be useful
}

"""
import json
import argparse

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from scapy.all import *

def get_key_dict(keylog):
    keys = {}
    with open(keylog, "r") as f:
        for line in f:
            if line.strip().startswith("{"):
                datum = json.loads(line.strip())
                keys[datum["tail"]] = datum
    return keys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('keylog')
    parser.add_argument('netcap')
    args = parser.parse_args()

    keys = get_key_dict(args.keylog)

    conns = {}
    for conn, record in MMTLSRecords(PcapReader(args.netcap)):
        last8 = (record[len(record)-8:].hex())
        if conn not in conns:
            conns[conn] = {"count": 0, "records": []}
        conns[conn]["records"].append(record)
        if last8 in keys:
            conns[conn]["count"] += 1
            # aad = (generate_aad(record, keys[last8], conns[conn]["count"]))
            outer_plaintext = decrypt_outer(record, keys[last8])
            last8 = outer_plaintext[-8:].hex()
            if last8 in keys:
                metadata, plaintext = decrypt_inner(outer_plaintext, keys[last8])
                print(json.dumps({"metadata": metadata.hex(), "plaintext": plaintext.hex()}))

def conn_tuple(pkt):
    if TCP not in pkt:
        return None
    return (tuple(sorted([pkt[IP].src, pkt[IP].dst])),
            tuple(sorted([pkt[TCP].sport, pkt[TCP].dport])))

MMTLS_MAGICBYTES = b"\xf1\x04"
def MMTLSRecords(pcapReader):
    for pkt in pcapReader:
        if TCP not in pkt: continue
        payload = bytes(pkt[TCP].payload)
        while MMTLS_MAGICBYTES in payload:
            record_start = payload.find(MMTLS_MAGICBYTES) - 1
            record_len = int.from_bytes(payload[record_start+3:record_start+5], "big") + 5
            yield conn_tuple(pkt), payload[record_start:record_start + record_len]
            payload = payload[record_start + record_len:]

def decrypt_outer(record, keydata):
    # print(keydata)
    cipher = AES.new(bytes.fromhex(keydata["key"]), AES.MODE_GCM, nonce=bytes.fromhex(keydata["nonce"]))
    # print(aad)
    cipher.update(bytes.fromhex(keydata["metadata"]))
    ciphertext = record[5:-16]
    tag = record[-16:]
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
    except:
        raise "MAC not verified"
    return plaintext

INNER_CIPHER_FLAG = b'\x00\x00'
def decrypt_inner(inner_record, keydata):
    cipher_start = inner_record.rfind(INNER_CIPHER_FLAG)
    ciphertext = inner_record[cipher_start+2:]
    cipher = AES.new(bytes.fromhex(keydata["key"]), AES.MODE_CBC,
                     iv=bytes.fromhex(keydata["nonce"]))
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return inner_record[:cipher_start], plaintext

if __name__ == "__main__":
    main()
