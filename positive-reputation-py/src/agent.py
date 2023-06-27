import logging
import sys
from os import environ

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3

from datetime import datetime, timedelta

from src.constants import MIN_NONCE, MIN_AGE_IN_DAYS, ADDRESS_CACHE_SIZE, FIRST_TXS_CACHE_SIZE
from src.findings import PositiveReputationFindings
from src.blockexplorer import BlockExplorer
from src.storage import get_secrets

SECRETS_JSON = get_secrets()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
blockexplorer = BlockExplorer(web3.eth.chain_id)

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

ADDRESS_CACHE = set()
FIRST_TXS = {}
CHAIN_ID = -1


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global ADDRESS_CACHE
    ADDRESS_CACHE = set()

    global FIRST_TXS
    FIRST_TXS = {}

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


def detect_positive_reputation(w3, blockexplorer, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    logging.info(f"Analyzing transaction {transaction_event.transaction.hash} on chain {w3.eth.chain_id}")

    global CHAIN_ID
    findings = []

    # get the nonce of the sender
    global ADDRESS_CACHE
    if not transaction_event.transaction.from_.lower() in ADDRESS_CACHE:
        if transaction_event.transaction.nonce >= MIN_NONCE:
            if transaction_event.transaction.from_.lower() in FIRST_TXS:
                logging.info(f"Checking first tx of address from cache {transaction_event.transaction.from_}")
                first_tx = FIRST_TXS[transaction_event.transaction.from_.lower()]
            else:
                logging.info(f"Checking first tx of address with blockexplorer {transaction_event.transaction.from_}")
                first_tx = blockexplorer.get_first_tx(transaction_event.transaction.from_)
                update_first_tx_cache(transaction_event.transaction.from_, first_tx)

            if first_tx < datetime.now() - timedelta(days=MIN_AGE_IN_DAYS):
                update_address_cache(transaction_event.transaction.from_.lower())
                findings.append(PositiveReputationFindings.positive_reputation(transaction_event.transaction.from_, CHAIN_ID))

    return findings


def update_first_tx_cache(address: str, first_tx: datetime):
    global FIRST_TXS
    if len(FIRST_TXS) >= FIRST_TXS_CACHE_SIZE:
        FIRST_TXS.pop(0)
    FIRST_TXS[address.lower()] = first_tx


def update_address_cache(address: str):
    global ADDRESS_CACHE
    if len(ADDRESS_CACHE) >= ADDRESS_CACHE_SIZE:
        ADDRESS_CACHE.pop(0)
    ADDRESS_CACHE.add(address)


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_positive_reputation(w3, blockexplorer, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
