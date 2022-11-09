import logging
import sys

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3

from src.constants import TORNADO_CASH_ADDRESSES, TORNADO_CASH_WITHDRAW_TOPIC
from src.findings import FundingTornadoCashFindings

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


def detect_funding(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global ACCOUNT_TO_TORNADO_CASH_BLOCKS
    global ACCOUNT_QUEUE

    logging.info(f"Analyzing transaction {transaction_event.transaction.hash} on chain {w3.eth.chain_id}")

    findings = []

    for log in transaction_event.logs:
        if (log.address.lower() in TORNADO_CASH_ADDRESSES[w3.eth.chain_id] and TORNADO_CASH_WITHDRAW_TOPIC in log.topics):

            #  0x000000000000000000000000a1b4355ae6b39bb403be1003b7d0330c811747db1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660            
            to_address = Web3.toChecksumAddress(log.data[26:66])

            if(w3.eth.get_transaction_count(to_address, block_identifier=transaction_event.block_number) == 0):
                logging.info(f"Identified new account {to_address} on chain {w3.eth.chain_id}")
                findings.append(FundingTornadoCashFindings.funding_tornado_cash(to_address))
            else:
                logging.info(f"Identified existing account {to_address} on chain {w3.eth.chain_id}. Wont emit finding.")

    logging.info(f"Return {transaction_event.transaction.hash}")
            
    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
