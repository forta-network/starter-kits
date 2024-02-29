import asyncio
from web3 import Web3, AsyncWeb3
import logging
import sys

from forta_bot import scan_ethereum, TransactionEvent, get_chain_id, run_health_check
from hexbytes import HexBytes
from async_lru import alru_cache

from constants import *
from findings import FundingUnionChainFindings

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

async def is_new_account(w3, address, block_number):
    if address is None:
        return True
    return await w3.eth.get_transaction_count(Web3.to_checksum_address(address), block_number) == 0


async def detect_union_chain_funding(w3, transaction_event):
    global LOW_VOL_ALERT_COUNT
    global NEW_EOA_ALERT_COUNT
    global DENOMINATOR_COUNT
    global CHAIN_ID

    print(f"Transaction hash: {transaction_event.hash}")

    findings = []

    if (not transaction_event.to):
        return findings

    native_value = transaction_event.transaction.value / 1e18

    is_new_acc = await is_new_account(w3, transaction_event.to, transaction_event.block_number)
    is_contr = await is_contract(w3, transaction_event.to)

    if (native_value > 0 and (native_value < UNION_CHAIN_THRESHOLD or is_new_acc) and not is_contr):
        DENOMINATOR_COUNT += 1

    """
    if the transaction is from Union Chain, and not to a contract: check if transaction count is 0,
    else check if value sent is less than the threshold
    """
    if (transaction_event.from_ == UNION_CHAIN_ADDRESS and not is_contr):
        if is_new_acc:
            NEW_EOA_ALERT_COUNT += 1
            score = str((1.0 * NEW_EOA_ALERT_COUNT) / DENOMINATOR_COUNT)
            findings.append(FundingUnionChainFindings.funding_union_chain(transaction_event, "new-eoa", score, CHAIN_ID))
        elif native_value < UNION_CHAIN_THRESHOLD:
            LOW_VOL_ALERT_COUNT += 1
            score = str((1.0 * LOW_VOL_ALERT_COUNT) / DENOMINATOR_COUNT)
            findings.append(FundingUnionChainFindings.funding_union_chain(transaction_event, "low-amount", score, CHAIN_ID))
    return findings


async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider):
    return await detect_union_chain_funding(web3, transaction_event)


async def main():
    initialize()
    
    await asyncio.gather(
        scan_ethereum({
            'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "e698634d-79c2-44fe-adf8-f7dac20dd33c",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        run_health_check()
    )

if __name__ == "__main__":
    asyncio.run(main())