import argparse
from protocol_data import ProtocolData
from stamp_and_extend import StampExtendProtocol
from web3 import Web3


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TSA Client")
    parser.add_argument(
        "--password", default="", type=str,
        help="Provide a password to recover encrypted file. " +
        "Remember it well because there is no recovery for it."
    )
    args = parser.parse_args()
    data = ProtocolData(args.password)
    stamp_extend = StampExtendProtocol(data)

    alchemy_url = "https://eth-sepolia.g.alchemy.com/v2/HefAK5GwS1wWZFGRM-TBkfG3JhWBQgD5"
    w3 = Web3(Web3.HTTPProvider(alchemy_url))

    # Print if web3 is successfully connected
    print(w3.isConnected())
    print(stamp_extend.A, stamp_extend.h,
          stamp_extend.c1, stamp_extend.HS0, sep="\n")
