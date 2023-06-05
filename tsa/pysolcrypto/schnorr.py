from __future__ import print_function
from utils import hashs
from altbn128 import hashpn, hashsn, mulmodn, sbmul, addmodn, randsn
from past.builtins import long
from py_ecc.bn128 import add, multiply


def _hash_points_and_message(a, b, m): return hashsn(hashpn(a, b), m)


def schnorr_create(secret, message, k=randsn(), point=None):
    assert isinstance(secret, long)
    assert isinstance(message, long)
    assert isinstance(k, long)
    A = multiply(point, secret) if point else sbmul(secret)
    X = multiply(point, k) if point else sbmul(k)
    h = hashs(X[0].n, X[1].n, message)
    s = addmodn(k, mulmodn(secret, h))
    return A, X, s


def schnorr_calc(A, X, message):
    assert isinstance(message, long)
    h = hashs(X[0].n, X[1].n, message)
    XAh = add(X, multiply(A, h))
    return XAh


def schnorr_verify(A, X, s, message, point=None):
    sG = multiply(point, s) if point else sbmul(s)
    proof = schnorr_calc(A, X, message)
    return sG == proof


if __name__ == "__main__":
    s = 19977808579986318922850133509558564821349392755821541651519240729619349670944
    m = 19996069338995852671689530047675557654938145690856663988250996769054266469975
    A, X, S = schnorr_create(s, m)
    print(schnorr_verify(A, X, S, m))
