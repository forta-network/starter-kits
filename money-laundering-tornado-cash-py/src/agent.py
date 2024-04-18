import logging
import sys

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3
from os import environ

from src.constants import (TORNADO_CASH_ADDRESSES, TORNADO_CASH_DEPOSIT_TOPIC)
from src.findings import MoneyLaunderingTornadoCashFindings
from src.storage import get_secrets

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

secrets = None

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    global secrets

    try:
        # retrieve secrets
        if secrets is None:
            secrets = get_secrets()
            logging.info("Retrieved secrets successfully.")
    except Exception as e:
        logging.error("Error retrieving secrets.")
        raise e

    environ["ZETTABLOCK_API_KEY"] = secrets['apiKeys']['ZETTABLOCK']

def detect_money_laundering(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list: 
    findings = []
    account = Web3.toChecksumAddress(transaction_event.from_)

    if transaction_event.to is None:
        return findings
    value = transaction_event.transaction.value
    for log in transaction_event.logs:
        if (transaction_event.transaction.value is not None and value > 0 and
           log.address in TORNADO_CASH_ADDRESSES and TORNADO_CASH_DEPOSIT_TOPIC in log.topics):
                findings.append(MoneyLaunderingTornadoCashFindings.possible_money_laundering_tornado_cash(
                    account, value, CHAIN_ID))
    
    logging.info(f"Return {transaction_event.transaction.hash}")

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_money_laundering(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
