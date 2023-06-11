import argparse
from protocol_data import ProtocolData
from stamp_and_extend import StampExtendProtocol
from web3 import Web3
import json
import asyncio

with open("../api_key") as file:
    api_key = json.loads(file.read())
alchemy_url = "https://eth-sepolia.g.alchemy.com/v2/" + api_key
se_address = "paste address here"
with open("../abi") as file:
    se_abi = json.loads(file.read())


def handle_timestamp_event(event):
    """Handle an incoming TimeStampRequested event."""
    print(Web3.toJSON(event))
    # TODO make a timestamp and publish it


async def log_loop(event_filter, poll_interval):
    while True:
        for TimeStampRequested in event_filter.get_new_entries():
            handle_timestamp_event(TimeStampRequested)
        await asyncio.sleep(poll_interval)


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

    w3 = Web3(Web3.HTTPProvider(alchemy_url))

    # Print if web3 is successfully connected
    print(w3.is_connected())
    # Testing the contract, export the initial values
    """
    print(stamp_extend.A, stamp_extend.h,
          stamp_extend.c1, stamp_extend.HS0, sep="\n")
    print("Timestamp for 1736..")
    print(stamp_extend.create_timestamp(1736109339377034722022031384259527484745846388714740965905228))
    """
    # TODO implement event handling
    """
    contract = w3.eth.contract(address=se_address, abi=se_abi)
    event_filter = contract.events.PairCreated.createFilter(fromBlock='latest')
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            asyncio.gather(
                log_loop(event_filter, 2)))
    finally:
        # close loop to free up system resources
        loop.close()
    """
