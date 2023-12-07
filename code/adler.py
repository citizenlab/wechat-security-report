import unittest
import os
import zlib

def A(x):
    return (1 + sum(x)) % 65521

def B(x):
    total = 0
    for i in range(len(x)):
        total += (len(x) - i) * x[i]
    return (len(x) + total) % 65521

# given adler32(x + y) and y, find adler32(x)
def recover_adler32_prefix(adler32_xy, y):
    Ay = A(y)
    By = B(y)
    # first, recover Axy and Bxy such that adler32(x + y) = Axy + 65536 * Bxy
    Axy = adler32_xy % 65536
    Bxy = adler32_xy // 65536
    assert Axy < 65521
    assert Bxy < 65521
    # Axy = (Ax + Ay - 1) mod 65521
    #   => Ax + q * 65521 = Axy + 1 - Ay
    # since the rhs is known, we can solve for Ax
    Ax = (Axy + 1 - Ay) % 65521
    # Bxy = (len(x) * (Ax - 1) mod 65521) + Bx - 65521 * p = Bxy - By
    #   => Bx - 65521 * p = Bxy - By - len(x) * (Ax - 1) mod 65521
    Bx = (Bxy - By - (len(y) * (Ax - 1))) % 65521
    return Ax + 65536 * Bx

# given adler32(x + y), return adler32(x + new_y)
def replace_adler32_suffix(adler32_xy, y, new_y):
    alder32_x = recover_adler32_prefix(adler32_xy, y)
    Ax = alder32_x % 65536
    Bx = alder32_x // 65536
    Ax_newy = (Ax + A(new_y) - 1) % 65521
    Bx_newy = ((len(new_y) * (Ax - 1)) % 65521 + Bx + B(new_y)) % 65521
    return Ax_newy + 65536 * Bx_newy

class Tests(unittest.TestCase):
    def test_A_and_B(self):
        x = b'whats up gamers' * 100
        self.assertEqual(zlib.adler32(x), A(x) + 65536 * B(x))

    def test_recovery(self):
        x = b'whats up'
        y = b' gamers'
        self.assertEqual(zlib.adler32(x), recover_adler32_prefix(zlib.adler32(x + y), y))

    def test_bigger_recover(self):
        x = os.urandom(4000)
        y = os.urandom(1000)
        self.assertEqual(zlib.adler32(x), recover_adler32_prefix(zlib.adler32(x + y), y))
    
    def test_pathological(self):
        x = ([255] * 256) + [240]
        x = bytes(x)
        y = os.urandom(1000)
        self.assertEqual(zlib.adler32(x), recover_adler32_prefix(zlib.adler32(x + y), y))

    def test_change_suffix(self):
        x = b'whats up'
        y = b' gamers'
        new_y = b' fellow professionals'
        self.assertEqual(zlib.adler32(x + new_y), replace_adler32_suffix(zlib.adler32(x + y), y, new_y))

unittest.main()
