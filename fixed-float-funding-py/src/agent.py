import logging
import sys

from forta_agent import get_json_rpc_url, Web3
from hexbytes import HexBytes
from functools import lru_cache

from src.constants import *
from src.findings import FundingFixedFloatFindings

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


def is_new_account(w3, address, block_number):
    return w3.eth.get_transaction_count(Web3.toChecksumAddress(address), block_number) == 0


def detect_fixed_float_funding(w3, transaction_event):
    global LOW_VOL_ALERT_COUNT
    global NEW_EOA_ALERT_COUNT
    global DENOMINATOR_COUNT
    global CHAIN_ID

    fixed_float_threshold = FIXED_FLOAT_THRESHOLD[CHAIN_ID]

    findings = []

    if (not transaction_event.to):
        return findings

    native_value = transaction_event.transaction.value / 10e17

    if (native_value > 0 and (native_value < fixed_float_threshold or is_new_account(w3, transaction_event.to, transaction_event.block_number)) and not is_contract(w3, transaction_event.to)):
        DENOMINATOR_COUNT += 1


    """
    if the transaction is from Fixed Float, and not to a contract: check if transaction count is 0,
    else check if value sent is less than the threshold
    """
    if (transaction_event.from_ == FIXED_FLOAT_ADDRESS[CHAIN_ID] and not is_contract(w3, transaction_event.to)):
        if is_new_account(w3, transaction_event.to, transaction_event.block_number):
            NEW_EOA_ALERT_COUNT += 1
            score = (1.0 * NEW_EOA_ALERT_COUNT) / DENOMINATOR_COUNT
            findings.append(FundingFixedFloatFindings.funding_fixed_float(transaction_event, "new-eoa", score, CHAIN_ID))
        elif native_value < fixed_float_threshold:
            LOW_VOL_ALERT_COUNT += 1
            score = (1.0 * LOW_VOL_ALERT_COUNT) / DENOMINATOR_COUNT
            findings.append(FundingFixedFloatFindings.funding_fixed_float(transaction_event, "low-amount", score, CHAIN_ID))
    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event):
        return detect_fixed_float_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
