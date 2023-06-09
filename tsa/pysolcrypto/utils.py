import sys
import binascii
import math
from functools import reduce
from os import urandom
from Crypto.Hash import keccak


def quote(x): return '"' + str(x) + '"'


def quotemany(*x): return ','.join(map(quote, x))
def quotelist(x): return '[' + quotemany(*x) + ']'


safe_ord = ord if sys.version_info.major == 2 else lambda x: x if isinstance(
    x, int) else ord(x)


def bytes_to_int(x): return reduce(
    lambda o, b: (o << 8) + safe_ord(b), [0] + list(x))


def packl(lnum):
    if lnum == 0:
        return b'\0'
    s = hex(lnum)[2:].rstrip('L')
    if len(s) & 1:
        s = '0' + s
    return binascii.unhexlify(s)


int_to_big_endian = packl


def zpad(x, length): return b'\x00' * max(0, length - len(x)) + x


def tobe256(v): return zpad(int_to_big_endian(v), 32)


def hashs(*x):
    data = b''.join(map(tobe256, x))
    keccak_hash = keccak.new(digest_bits=256)
    return bytes_to_int(keccak_hash.update(data).digest())


def randb256(): return urandom(32)


def bit_clear(n, b): return n ^ (1 << (b-1)) if n & 1 << (b-1) else n


def bit_set(n, b): return n | (1 << (b-1))


def bit_test(n, b): return 0 != (n & (1 << (b-1)))


def powmod(a, b, n):
    c = 0
    f = 1
    k = int(math.log(b, 2))
    while k >= 0:
        c *= 2
        f = (f*f) % n
        if b & (1 << k):
            c += 1
            f = (f*a) % n
        k -= 1
    return f


if __name__ == "__main__":
    assert bin(bit_clear(3, 1)) == '0b10'
    assert bin(bit_clear(3, 2)) == '0b1'
    assert bin(bit_set(0, 1)) == '0b1'
