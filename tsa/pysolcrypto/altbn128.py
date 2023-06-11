from random import randint
from past.builtins import long

from py_ecc.bn128 import multiply, curve_order, G1, field_modulus, FQ

from .utils import hashs, bytes_to_int, powmod


def asint(x): return x.n if isinstance(x, FQ) else x


def randsn(): return randint(1, curve_order - 1)
def randsp(): return randint(1, field_modulus - 1)
def sbmul(s): return multiply(G1, asint(s))


def hashsn(*x): return hashs(*x) % curve_order
def hashpn(*x): return hashsn(*[item.n for sublist in x for item in sublist])
def hashp(*x): return hashs(*[item.n for sublist in x for item in sublist])
def addmodn(x, y): return (x + y) % curve_order
def addmodp(x, y): return (x + y) % field_modulus
def mulmodn(x, y): return (x * y) % curve_order
def mulmodp(x, y): return (x * y) % field_modulus
def submodn(x, y): return (x - y) % curve_order
def submodp(x, y): return (x - y) % field_modulus
def negp(x): return (x[0], -x[1])


def evalcurve(x):
    a = 5472060717959818805561601436314318772174077789324455915672259473661306552146
    beta = addmodp(mulmodp(mulmodp(x, x), x), 3)
    y = powmod(beta, a, field_modulus)
    return (beta, y)


def isoncurve(x, y):
    beta = addmodp(mulmodp(mulmodp(x, x), x), 3)
    return beta == mulmodp(y, y)


def hashtopoint(x):
    assert isinstance(x, long)
    x = x % curve_order
    while True:
        beta, y = evalcurve(x)
        if beta == mulmodp(y, y):
            assert isoncurve(x, y)
            return FQ(x), FQ(y)
        x = addmodn(x, 1)


if __name__ == "__main__":
    # Sanity test
    beta, y = evalcurve(1)
    assert mulmodp(y, y) == beta
    assert y == 2

    # Compatibility test
    from hashlib import sha256
    z = bytes_to_int(sha256('hello world').digest())
    x, y = hashtopoint(z)
    assert x == 18149469767584732552991861025120904666601524803017597654373315627649680264678
    assert y == 18593544354303197021588991433499968191850988132424885073381608163097237734820

    # Compatibility with:
    # uint256(keccak256(uint256(1), uint256(2), uint256(3))) % Curve.N();
    assert hashsn(
        1, 2, 3
    ) == 5999809398626971894156481321441750001229812699285374901473004231265197659290
