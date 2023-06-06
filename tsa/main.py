import argparse
from protocol_data import ProtocolData


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
