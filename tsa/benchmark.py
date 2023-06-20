from matplotlib import pyplot as plt
from memory_profiler import profile
from statistics import mean
from sys import getsizeof
from typing import Any, List
from pathlib import Path
from protocol_data import ProtocolData, DataType
from pysolcrypto.altbn128 import sbmul, randsn, hashs
from pysolcrypto.pedersen import pedersen_com
from pysolcrypto.schnorr import schnorr_create

import os
import time


class StampExtendProtocolTest:
    """Version of the protocol for benchmarking. No encrypted storage."""

    def __init__(self) -> None:
        # Generate initial values
        self.a = randsn()
        self.A = sbmul(self.a)
        self.h = sbmul(randsn())
        self.P = [{"k": randsn(), "l": randsn()}]
        self.c1 = pedersen_com(
            self.P[0]["k"], self.P[0]["l"], self.h
        )
        self.C = {"1": (self.c1[0].n, self.c1[1].n)}
        cert_m = hashs(self.A[0].n, self.A[1].n, self.c1[0].n, self.c1[1].n)
        _, X, S = schnorr_create(self.a, cert_m)
        self.HS = {"0": {"X": (X[0].n, X[1].n), "s": S, "l": 0, "i": 0,
                         "data": cert_m}}

    def create_timestamp(self, data: Any):
        """Create a timestamp for the submitted data."""
        # Load data
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
        self.C[str(2*i)] = (c_2i[0].n, c_2i[1].n)
        self.C[str((2*i)+1)] = (c_2i1[0].n, c_2i1[1].n)
        self.P.append({"k": k_2i, "l": l_2i})
        self.P.append({"k": k_2i1, "l": l_2i1})
        kl = self.P.pop(0)
        # Pop i-th pair of exponents
        k_i = kl["k"]
        l_i = kl["l"]
        # Message (H(HSi−1), Hi, c2i, c2i+1, l, i)
        hs1 = self.HS[str(i-1)]
        hs1_hash = hashs(hs1["X"][0], hs1["X"][1],
                         hs1["s"], hs1["l"], hs1["i"], hs1["data"])
        m = hashs(hs1_hash, data, c_2i[0].n,
                  c_2i[1].n, c_2i1[0].n, c_2i1[1].n, l_i, i)
        # Form a timestamp HS_i
        _, X, s = schnorr_create(self.a, m, k_i)
        T_i = {"X": (X[0].n, X[1].n), "s": s, "l": l_i, "i": i, "data": data}
        self.HS[str(i)] = T_i
        # Return the timestamp
        return T_i, self.C[str(2*i)], self.C[str((2*i)+1)]


test_protocol = StampExtendProtocolTest()
ts_create_times = []


def graph_ts_create(times: List[int]):
    plot_x = [i + 1 for i in range(len(times))]
    plt.scatter(x=plot_x, y=times, c='green', s=2)
    plt.xlabel('Index of a timestamp')
    plt.ylabel('Timestamp creation time in seconds')
    plt.title(
        "Duration of timestamp creation based on number of timestamps issued"
    )
    plt.savefig('ts_create_times.png')


@profile
def test_ts_create():
    # time test for timestamps
    for _ in range(100):
        #start = time.perf_counter()
        test_protocol.create_timestamp(randsn())
        #end = time.perf_counter()
        #ts_create_times.append(end-start)


if __name__ == "__main__":
    password = "benchmark"
    data_storage = ProtocolData(password, Path().absolute())
    test_ts_create()
    """
    graph_ts_create(ts_create_times)
    print(f"Mean timestamp creation time: {mean(ts_create_times)}")

    # Test size of encrypted storage
    data_storage.write_data(DataType.P, test_protocol.P)
    data_storage.write_data(DataType.C, test_protocol.C)
    data_storage.write_data(DataType.HS, test_protocol.HS)

    for file in [data_storage._P_path, data_storage._C_path, data_storage._HS_path]:
        stats = os.stat(file)
        print(
            f"Encrypted {file} size for 10 K timestamps: {stats.st_size / (1024 * 1024)} MB")

    # Print size of unencrypted data
    print(
        f"Nonencrypted P size for 10 K timestamps: {getsizeof(test_protocol.P) / (1024 * 1024)} MB")
    print(
        f"Nonencrypted C size for 10 K timestamps: {getsizeof(test_protocol.C) / (1024 * 1024)} MB")
    print(
        f"Nonencrypted HS size for 10 K timestamps: {getsizeof(test_protocol.HS) / (1024 * 1024)} MB")
    """
