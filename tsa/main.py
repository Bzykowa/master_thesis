import argparse
from protocol_data import ProtocolData
from stamp_and_extend import StampExtendProtocol
from web3 import Web3
import json
import asyncio

# Initialize the connection parameters
with open("../api_key") as file:
    api_key = file.read()

alchemy_url = "https://eth-sepolia.g.alchemy.com/v2/" + api_key
se_address = "0xBC5B10a20149d9A473a43Ab386a436223Da12220"

with open("../abi") as file:
    se_abi = json.loads(file.read())

# Connect to web3
w3 = Web3(Web3.HTTPProvider(alchemy_url))
print(w3.is_connected())
contract = w3.eth.contract(address=se_address, abi=se_abi)


def handle_timestamp_event(event, se: StampExtendProtocol):
    """Handle an incoming TimeStampRequested event."""
    print(Web3.toJSON(event))
    # TODO make a timestamp and publish it


async def log_loop(event_filter, poll_interval, se: StampExtendProtocol):
    """Check for new events in a specified interval."""
    while True:
        for TimeStampRequested in event_filter.get_new_entries():
            handle_timestamp_event(TimeStampRequested, se)
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
    # Initialize the encrypted data
    data = ProtocolData(args.password)
    stamp_extend = StampExtendProtocol(data)

    """
    # Testing the contract, export the initial values
    print(stamp_extend.A, stamp_extend.h,
          stamp_extend.c1, stamp_extend.HS0, sep="\n")
    # Test of verification
    #print("Timestamp for 1736..")
    #print(stamp_extend.create_timestamp(1736109339377034722022031384259527484745846388714740965905228))
    """
    # TODO implement checking the backlog in the contract
    event_filter = contract.events.TimeStampRequested.createFilter(
        fromBlock='latest'
    )
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            asyncio.gather(
                log_loop(event_filter, 2, stamp_extend)
            )
        )
    finally:
        # close loop to free up system resources
        loop.close()
