
def hexdump(bytes):
    for i in range(0, len(bytes) // 16):
        for j in range(0, 16):
            print(f'{bytes[i*16+j]:02x} ', end='')
        print()

def bytestring_to_bytes(s):
    return bytes.fromhex(s.replace(' ', ''))
