import json
import logging
import sys
import asyncio
from web3 import Web3, AsyncWeb3

from forta_bot import scan_ethereum, scan_polygon, TransactionEvent, get_chain_id, run_health_check
from hexbytes import HexBytes
from async_lru import alru_cache

from constants import *
from findings import FundingRailgunFindings

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
    CHAIN_ID = get_chain_id()

@alru_cache(maxsize=100000)
async def is_contract(w3, address):
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = await w3.eth.get_code(Web3.to_checksum_address(address))
    return code != HexBytes('0x')

@alru_cache(maxsize=100000)
async def is_new_account(w3, address, block_number):
    if address is None:
        return True
    return await w3.eth.get_transaction_count(Web3.to_checksum_address(address), block_number) == 0


async def detect_railgun_funding(w3, transaction_event):
    global LOW_VOL_ALERT_COUNT
    global NEW_EOA_ALERT_COUNT
    global DENOMINATOR_COUNT
    global CHAIN_ID
    
    relay_function_invocations = transaction_event.filter_function(RELAY_FUNCTION_ABI, RAILGUN_ADDRESSES[CHAIN_ID])

    if len(relay_function_invocations) == 0:
        return []

    DENOMINATOR_COUNT += 1

    contract = w3.eth.contract(abi=[json.loads(TRANSFER_FUNCTION_ABI)])

    transfer_calldata = [
    '0x' + call.hex()
    for invocation in relay_function_invocations
    for calls in invocation[1]["_actionData"][-1]
    for call in calls
    if isinstance(call, bytes) and call.hex().startswith(RAILGUN_TRANSFER_FUNCTION_SIG) 
    ]

    # Decode and extract 'to' address from the calldata
    to_addresses = [
        transfer[1]
        for calldata in transfer_calldata
        for transfer in contract.decode_function_input(calldata)[1]['_transfers']
    ]
    
    if len(to_addresses) != 1:
        return []
    
    to_address = to_addresses[0]

    native_value = 0
    if CHAIN_ID in [1, 56, 137]:
        wrapped_native_token_withdrawal_events = transaction_event.filter_log(WITHDRAWAL_EVENT_ABI, WRAPPED_NATIVE_TOKEN_ADDRESSES[CHAIN_ID])

        if len(wrapped_native_token_withdrawal_events) != 1:
            return []

        native_value = wrapped_native_token_withdrawal_events[0]['args']['wad'] / 1e18
    elif CHAIN_ID == 42161:
        wrapped_native_token_transfer_events = transaction_event.filter_log(ERC20_TRANSFER_EVENT_ABI, WRAPPED_NATIVE_TOKEN_ADDRESSES[CHAIN_ID])

        if len(wrapped_native_token_transfer_events) == 0:
            return []

        for transfer in wrapped_native_token_transfer_events:
            if transfer['args']['to'] == ZERO_ADDRESS:
                native_value = transfer['args']['value'] / 1e18
                break

    if native_value == 0:
        return []

    railgun_threshold = RAILGUN_THRESHOLDS[CHAIN_ID]

    findings = []

    is_new_account_flag = await is_new_account(w3, to_address, transaction_event.block_number)
    is_contr = await is_contract(w3, transaction_event.to)

    if not is_contr:
        if is_new_account_flag or native_value < railgun_threshold:
            
            alert_type = "new-eoa" if is_new_account_flag else "low-amount"
            alert_count = NEW_EOA_ALERT_COUNT if is_new_account_flag else LOW_VOL_ALERT_COUNT
            alert_count += 1

            score = str((1.0 * alert_count) / DENOMINATOR_COUNT)
            findings.append(FundingRailgunFindings.funding_railgun(transaction_event, native_value, to_address, alert_type, score, CHAIN_ID))

    return findings


async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider):
    return await detect_railgun_funding(web3, transaction_event)

async def main():
    initialize()
    
    await asyncio.gather(
        scan_ethereum({
            'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "e698634d-79c2-44fe-adf8-f7dac20dd33c",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        scan_polygon({
            'rpc_url': "https://polygon-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "b9017deb-b785-48f8-bfb3-771f31190845",
            'local_rpc_url': "137",
            'handle_transaction': handle_transaction
        }),
        run_health_check()
    )

if __name__ == "__main__":
    asyncio.run(main())