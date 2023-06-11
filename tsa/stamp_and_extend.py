from typing import Any
from protocol_data import ProtocolData, DataType
from pysolcrypto.altbn128 import sbmul, randsn, hashs
from pysolcrypto.pedersen import pedersen_com
from pysolcrypto.schnorr import schnorr_create


class StampExtendProtocol:
    def __init__(self, data_source: ProtocolData) -> None:
        # Load secret key and secret generator exponent
        self.ds = data_source
        keys = self.ds.get_data(DataType.SK)
        self.a = keys["a"]
        self.A = sbmul(self.a)
        self.h = sbmul(keys["h"])
        self.P = self.ds.get_data(DataType.P)
        self.C = self.ds.get_data(DataType.C)
        self.HS = self.ds.get_data(DataType.HS)
        self.HS0 = self.HS[0]
        self.c1 = self.C[0]

    def create_timestamp(self, data: Any):
        """Create a timestamp for the submitted data."""
        # Load data
        self.P = self.ds.get_data(DataType.P)
        self.C = self.ds.get_data(DataType.C)
        self.HS = self.ds.get_data(DataType.HS)
        i = len(self.HS)
        # Make (k_2i,l_2i) and (k_2i+1,l_2i+1)
        k_2i = randsn()
        k_2i1 = randsn()
        l_2i = randsn()
        l_2i1 = randsn()
        # Make future commitments c_2i and c_2i+1
        c_2i = pedersen_com(k_2i, l_2i, self.h)
        c_2i1 = pedersen_com(k_2i1, l_2i1, self.h)
        # Update P and C
        self.C[2*i] = (c_2i[0].n, c_2i[1].n)
        self.C[(2*i)+1] = (c_2i1[0].n, c_2i1[1].n)
        self.P.append({"k": k_2i, "l": l_2i})
        self.P.append({"k": k_2i1, "l": l_2i1})
        kl = self.P.pop(0)
        # Pop i-th pair of exponents
        k_i = kl["k"]
        l_i = kl["l"]
        # Message (H(HSi−1), Hi, c2i, c2i+1, l, i)
        hs1 = self.HS[i-1]
        hs1_hash = hashs(hs1["X"][0], hs1["X"][1],
                         hs1["s"], hs1["l"], hs1["i"], hs1["data"])
        m = hashs(hs1_hash, data, c_2i[0].n,
                  c_2i[1].n, c_2i1[0].n, c_2i1[1].n, l_i, i)
        # Form a timestamp HS_i
        _, X, s = schnorr_create(self.a, m, k_i)
        T_i = {"X": (X[0].n, X[1].n), "s": s, "l": l_i, "i": i, "data": data}
        self.HS[i] = T_i
        # Save data
        self.ds.write_data(DataType.P, self.P)
        self.ds.write_data(DataType.C, self.C)
        self.ds.write_data(DataType.HS, self.HS)
        # Return the timestamp
        return T_i
