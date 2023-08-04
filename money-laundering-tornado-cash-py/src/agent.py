import logging
import sys

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3
from os import environ

from src.constants import (TORNADO_CASH_ACCOUNTS_QUEUE_SIZE,
                           TORNADO_CASH_ADDRESSES, TORNADO_CASH_TRANSFER_AMOUNT_THRESHOLDS,
                           TORNADO_CASH_DEPOSIT_TOPIC,)
from src.findings import MoneyLaunderingTornadoCashFindings
from src.storage import get_secrets

SECRETS_JSON = get_secrets()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# dict of accounts to dicts of blocks to counts; e.g. # account 1, block 101, 1
ACCOUNT_QUEUE = []


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

    global ACCOUNT_QUEUE
    ACCOUNT_QUEUE = []

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


def detect_money_laundering(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global ACCOUNT_QUEUE

    logging.info(
        f"Analyzing transaction {transaction_event.transaction.hash} on chain {w3.eth.chain_id}")

    findings = []
    account = Web3.toChecksumAddress(transaction_event.from_)

    if transaction_event.to is None:
        return findings

    for log in transaction_event.logs:
        if (transaction_event.transaction.value is not None and transaction_event.transaction.value > 0 and
           Web3.toChecksumAddress(log.address) == TORNADO_CASH_ADDRESSES[w3.eth.chain_id] and TORNADO_CASH_DEPOSIT_TOPIC in log.topics):

            ACCOUNT_QUEUE.append(account)
            logging.info(
                f"Identified account {account} on chain {w3.eth.chain_id}")

            else:
                block_to_tx_count = ACCOUNT_TO_TORNADO_CASH_BLOCKS[account]


            #  maintain a size
            if len(ACCOUNT_QUEUE) > TORNADO_CASH_ACCOUNTS_QUEUE_SIZE:
                acc = ACCOUNT_QUEUE.pop(0)

    if account in ACCOUNT_QUEUE:
        logging.info(f"Account {account} total txs {total_txs}")

        tx_threshold = TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_ETH
        deposit_size = TORNADO_CASH_DEPOSIT_SIZE
        if w3.eth.chain_id == 137:
            tx_threshold = TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_MATIC
            deposit_size = TORNADO_CASH_DEPOSIT_SIZE_MATIC
        if w3.eth.chain_id == 56:
            tx_threshold = TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_BSC

        if total_txs >= tx_threshold:
            findings.append(MoneyLaunderingTornadoCashFindings.possible_money_laundering_tornado_cash(
                account, total_txs * deposit_size, CHAIN_ID))

    logging.info(f"Return {transaction_event.transaction.hash}")

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_money_laundering(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
