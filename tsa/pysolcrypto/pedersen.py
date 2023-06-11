"""
https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF
"""


from py_ecc.bn128 import add, multiply
from .altbn128 import sbmul


def pedersen_com(k_i, l_i, H):
    rt = multiply(H, l_i)
    lt = sbmul(k_i)
    return add(lt, rt)


def pedersen_unv(C, H, X, l_i):
    rt = multiply(H, l_i)
    return C == add(X, rt)


if __name__ == "__main__":
    k_i = 1997780857998631892285013350955856482134939275582154165151924072961934967094
    l_i = 1999606933899585267168953004767555765493814569085666398825099676905426646997
    h = 9642485650317736547022908278236968264307080196717164918177404064122340996525
    H = sbmul(h)
    X = sbmul(k_i)

    c = pedersen_com(k_i, l_i, H)
    print(pedersen_unv(c, H, X, l_i))
