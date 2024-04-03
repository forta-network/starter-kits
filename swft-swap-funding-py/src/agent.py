import logging
import sys
import asyncio

from forta_bot import TransactionEvent, scan_ethereum, run_health_check, get_chain_id
from hexbytes import HexBytes
from async_lru import alru_cache
from web3 import AsyncWeb3   

from constants import *
from findings import FundingSwftSwapFindings


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

async def initialize():
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
    CHAIN_ID = get_chain_id()

@alru_cache(maxsize=100000)
async def is_contract(w3, address):
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = await w3.eth.get_code(w3.to_checksum_address(address))
    return code != HexBytes('0x')

@alru_cache(maxsize=100000)
async def is_new_account(w3, address, block_number):
    return (await w3.eth.get_transaction_count(w3.to_checksum_address(address), block_number)) == 0


async def detect_swft_swap_funding(w3, transaction_event):
    global LOW_VOL_ALERT_COUNT
    global NEW_EOA_ALERT_COUNT
    global DENOMINATOR_COUNT
    global CHAIN_ID
    
    withdraw_eth_function_invocations = transaction_event.filter_function(WITHDRAW_ETH_FUNCTION_ABI, SWFT_SWAP_ADDRESS[CHAIN_ID])

    if len(withdraw_eth_function_invocations) == 0:
        return []

    recipient = withdraw_eth_function_invocations[0][1]['destination']
    native_value = withdraw_eth_function_invocations[0][1]['amount'] / 1e18

    if native_value == 0:
        return []

    DENOMINATOR_COUNT += 1

    swft_swap_threshold = SWFT_SWAP_THRESHOLDS[CHAIN_ID]

    findings = []

    is_new_account_flag = await is_new_account(w3, recipient, transaction_event.block_number)

    if not (await is_contract(w3, recipient)):
        if is_new_account_flag or native_value < swft_swap_threshold:
            
            alert_type = "new-eoa" if is_new_account_flag else "low-amount"
            alert_count = NEW_EOA_ALERT_COUNT if is_new_account_flag else LOW_VOL_ALERT_COUNT
            alert_count += 1

            score = (1.0 * alert_count) / DENOMINATOR_COUNT
            findings.append(FundingSwftSwapFindings.funding_swft_swap(transaction_event, native_value, recipient, alert_type, score, CHAIN_ID))

    return findings

async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider):
    return await detect_swft_swap_funding(web3, transaction_event)


async def main():
    await initialize()

    await asyncio.gather(
        scan_ethereum({
        'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
        'rpc_key_id': "ebbd1b21-4e72-4d80-b4f9-f605fee5eb68",
        'local_rpc_url': "1",
        'handle_transaction': handle_transaction
        }),
        run_health_check()
    )

if __name__ == "__main__":
    asyncio.run(main())