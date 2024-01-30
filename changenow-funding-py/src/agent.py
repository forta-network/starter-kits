import asyncio
from web3 import Web3, AsyncWeb3
import logging
import sys

# Could not import `get_chain_id`, `run_health_check`
from forta_bot import scan_ethereum, scan_base, TransactionEvent
from hexbytes import HexBytes
from functools import lru_cache

from constants import *
from findings import FundingChangenowFindings

# Initialize web3
# TODO: Update to not hardcode endpoint
web3 = Web3(Web3.HTTPProvider(""))

# Logging set up
root = logging.getLogger()
root.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

LOW_VOL_ALERT_COUNT = 0  # stats to emit anomaly score
NEW_EOA_ALERT_COUNT = 0  # stats to emit anomaly score
DENOMINATOR_COUNT = 0  # stats to emit anomaly score

def initialize():
    """
    Reset global variables.
    """
    global LOW_VOL_ALERT_COUNT
    LOW_VOL_ALERT_COUNT = 0

    global NEW_EOA_ALERT_COUNT
    NEW_EOA_ALERT_COUNT = 0

    global DENOMINATOR_COUNT
    DENOMINATOR_COUNT = 0

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id


@lru_cache(maxsize=100000)
async def is_contract(w3, address):
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = await w3.eth.get_code(Web3.to_checksum_address(address))
    return code != HexBytes('0x')


async def is_new_account(w3, address):
    return await w3.eth.get_transaction_count(Web3.to_checksum_address(address)) == 0


async def detect_changenow_funding(w3, transaction_event):
    global LOW_VOL_ALERT_COUNT
    global NEW_EOA_ALERT_COUNT
    global DENOMINATOR_COUNT
    global CHAIN_ID

    changenow_threshold = CHANGENOW_THRESHOLD[CHAIN_ID]
    changenow_addresses = CHANGENOW_ADDRESSES[CHAIN_ID]

    findings = []

    native_value = transaction_event.transaction.value / 10e17

    if (native_value > 0 and (native_value < changenow_threshold or await is_new_account(w3, transaction_event.to)) and not is_contract(w3, transaction_event.to)):
        DENOMINATOR_COUNT += 1

    """
    if the transaction is from ChangeNow, and not to a contract: check if transaction count is 0,
    else check if value sent is less than the threshold
    """
    if (transaction_event.from_ in changenow_addresses and not await is_contract(w3, transaction_event.to)):
        if await is_new_account(w3, transaction_event.to):
            NEW_EOA_ALERT_COUNT += 1
            score = (1.0 * NEW_EOA_ALERT_COUNT) / DENOMINATOR_COUNT
            findings.append(FundingChangenowFindings.funding_changenow(transaction_event, "new-eoa", score, CHAIN_ID))
        elif native_value < changenow_threshold:
            LOW_VOL_ALERT_COUNT += 1
            score = (1.0 * LOW_VOL_ALERT_COUNT) / DENOMINATOR_COUNT
            findings.append(FundingChangenowFindings.funding_changenow(transaction_event, "low-amount", score, CHAIN_ID))
    return findings


async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider):
    return await detect_changenow_funding(web3, transaction_event)

async def main():
    initialize()
    
    await asyncio.gather(
        scan_ethereum({
            'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "52191874-6755-4730-934b-fed0818f06ed",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        # scan_base({
        #     'rpc_url': "https://base.g.alchemy.com/v2",
        #     'rpc_key_id': "06ff4c43-d200-4dec-b09b-930834746f17",
        #     'local_rpc_url': "8453",
        #     'handle_transaction': handle_transaction
        # }),
        # run_health_check()
    )

# asyncio.run(main())