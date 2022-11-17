import logging
import sys

import forta_agent
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3

from src.constants import TRANSFER_TOPIC, MIN_TRANSFER_COUNT, MIN_TOKEN_COUNT, MIN_CONTRACT_COUNT
from src.findings import MEVAccountFinding

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')


def detect_mev(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    findings = []

    transfer_count = 0
    contracts = set()
    tokens = set()
    for log in transaction_event.logs:
        if TRANSFER_TOPIC in log.topics:
            transfer_count += 1
            tokens.add(log.address.lower())
            address1 = Web3.toChecksumAddress(log.topics[1][26:66].lower())
            address2 = Web3.toChecksumAddress(log.topics[2][26:66].lower())
            if is_contract(w3, address1):
                contracts.add(address1.lower())
            if is_contract(w3, address2):
                contracts.add(address2.lower())

    logging.info(f"tx {transaction_event.hash} transfer_count: {transfer_count} unique_token_count: {len(tokens)} unique_contract_address_count: {len(contracts)}")

    if transfer_count >= MIN_TRANSFER_COUNT and len(tokens) >= MIN_TOKEN_COUNT and len(contracts) >= MIN_CONTRACT_COUNT:
        findings.append(MEVAccountFinding.MEVAccount(transaction_event.from_, transfer_count, len(tokens), len(contracts)))

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_mev(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
