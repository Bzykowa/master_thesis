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

# Account data
acc_address = "0x894E98Fb9155BBFeE278c9F8EaD18B360b8Ec340"
with open("../acc_pk") as file:
    acc_pk = file.read()

# Connect to web3
w3 = Web3(Web3.HTTPProvider(alchemy_url))
print(f"Connected to web3: {w3.is_connected()}")
contract = w3.eth.contract(address=se_address, abi=se_abi)


def issue_timestamp(se: StampExtendProtocol, requester, data) -> None:
    T_i, c2i, c2i1 = se.create_timestamp(data)
    t_i = [T_i["X"][0], T_i["X"][1], T_i["s"],
           T_i["l"], T_i["i"], T_i["data"]]
    comms = [c2i[0], c2i[1], c2i1[0], c2i1[1]]
    # Build transaction
    timestamp_tx = contract.functions.issueTimeStamp(
        t_i, comms, requester
    ).build_transaction(
        {
            'from': acc_address,
            'nonce': w3.eth.get_transaction_count(acc_address),
        }
    )
    # Sign tx with PK
    tx_create = w3.eth.account.sign_transaction(timestamp_tx, acc_pk)

    # Send tx and wait for receipt
    tx_hash = w3.eth.send_raw_transaction(tx_create.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f'Tx successful with hash: { tx_receipt.transactionHash.hex() }')


def handle_timestamp_event(event, se: StampExtendProtocol):
    """Handle an incoming TimeStampRequested event."""
    event_json = Web3.to_json(event)
    event_data = json.loads(event_json)
    requester = event_data["args"]["requester"]
    data = event_data["args"]["data"]
    print("Received a request!")
    print(event_json)
    # Make a timestamp and publish it
    issue_timestamp(se, requester, data)


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
    # Checking the backlog in the contract
    pending_data = contract.functions.getPendingData().call()
    if (len(pending_data[0]) >= 1):
        print(f"You missed some requests: {pending_data}")
        for i in range(len(pending_data[0])):
            issue_timestamp(
                stamp_extend, pending_data[0][i], pending_data[1][i])

    # Monitor incoming events
    event_filter = contract.events.TimeStampRequested.create_filter(
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
