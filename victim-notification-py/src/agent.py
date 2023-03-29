import logging
import sys

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3

from src.constants import VICTIM_NOTIFIER_LIST
from src.findings import VictimNotificationFinding

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

CHAIN_ID = -1


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id


def detect_victim_notification(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global CHAIN_ID
    findings = []

    if transaction_event.to is None or transaction_event.from_ is None or transaction_event.transaction.data is None:
        return findings

    if transaction_event.from_.lower() in VICTIM_NOTIFIER_LIST and transaction_event.transaction.data != '0x':
        findings.append(VictimNotificationFinding.Victim(transaction_event.to, transaction_event.from_, CHAIN_ID))

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_victim_notification(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
