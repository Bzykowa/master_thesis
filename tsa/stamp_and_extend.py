from typing import Any
from protocol_data import ProtocolData, DataType
from pysolcrypto.altbn128 import sbmul

class StampExtendProtocol:
    def __init__(self, data_source: ProtocolData) -> None:
        # Load secret key and secret generator exponent
        self.ds = data_source
        keys = self.ds.get_data(DataType.SK)
        self.a = keys["a"]
        self.A = sbmul(self.a)
        self.h = sbmul(keys["h"])

    def create_timestamp(self, data: Any):
        """Create a timestamp for the submitted data."""
        self.P = self.ds.get_data(DataType.P)
        self.C = self.ds.get_data(DataType.C)
        self.HS = self.ds.get_data(DataType.HS)
        prev_i = len(self.C)
        # TODO finish
    