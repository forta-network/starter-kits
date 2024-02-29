import logging
import sys

from forta_agent import get_json_rpc_url, Web3
from hexbytes import HexBytes
from functools import lru_cache

from src.constants import *
from src.findings import FundingThorchainFindings

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


def detect_thorchain_funding(w3, transaction_event):
    global LOW_VOL_ALERT_COUNT
    global NEW_EOA_ALERT_COUNT
    global DENOMINATOR_COUNT
    global CHAIN_ID


    findings = []

    native_value = transaction_event.transaction.value / 1e18

    if native_value == 0:
        return findings
    
    thorchain_deposit_events = transaction_event.filter_log(DEPOSIT_EVENT_ABI, THORCHAIN_ROUTER_ADDRESS[CHAIN_ID])
    thorchain_transfer_out_events = transaction_event.filter_log(TRANSFER_OUT_EVENT_ABI, THORCHAIN_ROUTER_ADDRESS[CHAIN_ID])

    if len(thorchain_deposit_events) == 1:
        recipient = thorchain_deposit_events[0]['args']['to']
    elif len(thorchain_transfer_out_events) == 1 and thorchain_transfer_out_events[0]['args']['to'].lower() != transaction_event.from_: # ignore transfers back to the tx initiator in case of a failed native token transfer
        recipient = thorchain_transfer_out_events[0]['args']['to']
    else:
        return findings


    if (native_value > 0 and (native_value < THORCHAIN_THRESHOLDS[CHAIN_ID] or is_new_account(w3, recipient, transaction_event.block_number)) and not is_contract(w3, recipient)):
        DENOMINATOR_COUNT += 1

    """
    if the transaction is from Thorchain, and not to a contract: check if transaction count is 0,
    else check if value sent is less than the threshold
    """
    if (not is_contract(w3, recipient)):
        if is_new_account(w3, recipient, transaction_event.block_number):
            NEW_EOA_ALERT_COUNT += 1
            score = (1.0 * NEW_EOA_ALERT_COUNT) / DENOMINATOR_COUNT
            findings.append(FundingThorchainFindings.funding_thorchain(transaction_event, recipient, "new-eoa", score, CHAIN_ID))
        elif native_value < THORCHAIN_THRESHOLDS[CHAIN_ID]:
            LOW_VOL_ALERT_COUNT += 1
            score = (1.0 * LOW_VOL_ALERT_COUNT) / DENOMINATOR_COUNT
            findings.append(FundingThorchainFindings.funding_thorchain(transaction_event, recipient, "low-amount", score, CHAIN_ID))
    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event):
        return detect_thorchain_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
