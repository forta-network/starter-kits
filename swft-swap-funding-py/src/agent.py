import json
import logging
import sys

from forta_agent import get_json_rpc_url, Web3
from hexbytes import HexBytes
from functools import lru_cache

from src.constants import *
from src.findings import FundingSwftSwapFindings

# Initialize web3
web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

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
def is_contract(w3, address):
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')

@lru_cache(maxsize=100000)
def is_new_account(w3, address, block_number):
    return w3.eth.get_transaction_count(Web3.toChecksumAddress(address), block_number) == 0


def detect_swft_swap_funding(w3, transaction_event):
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

    is_new_account_flag = is_new_account(w3, recipient, transaction_event.block_number)

    if not is_contract(w3, recipient):
        if is_new_account_flag or native_value < swft_swap_threshold:
            
            alert_type = "new-eoa" if is_new_account_flag else "low-amount"
            alert_count = NEW_EOA_ALERT_COUNT if is_new_account_flag else LOW_VOL_ALERT_COUNT
            alert_count += 1

            score = (1.0 * alert_count) / DENOMINATOR_COUNT
            findings.append(FundingSwftSwapFindings.funding_swft_swap(transaction_event, native_value, recipient, alert_type, score, CHAIN_ID))

    return findings

def provide_handle_transaction(w3):
    def handle_transaction(transaction_event):
        return detect_swft_swap_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
