import logging
import sys
import requests
import pandas as pd

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3

from src.constants import LUABASE_QUERY
from src.findings import MaliciousAccountFundingFinding

import os

from dotenv import load_dotenv
load_dotenv()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

KNOWN_MALICIOUS_ACCOUNTS = dict()  # lower case address -> tag


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global KNOWN_MALICIOUS_ACCOUNTS
    KNOWN_MALICIOUS_ACCOUNTS = dict()


def update_known_malicious_accounts(chain_id: int):
    global KNOWN_MALICIOUS_ACCOUNTS
    KNOWN_MALICIOUS_ACCOUNTS = dict()

    logging.info("Updating known malicious accounts.")

    # Get all known malicious accounts from LuaBase
    sql = LUABASE_QUERY[chain_id]
    url = "https://q.luabase.com/run"
    payload = {
        "block": {
            "details": {
                "sql": sql,
                "limit": 50000,
            }
        },
        "api_key": os.environ.get('LUABASE_API_KEY')
    }

    headers = {"content-type": "application/json"}
    try: 
        response = requests.request("POST", url, json=payload, headers=headers)
        data = response.json()

        KNOWN_MALICIOUS_ACCOUNTS = pd.DataFrame(data["data"]).reset_index(drop=True).set_index("address").to_dict(orient="index")
        logging.info(f"Obtained {len(KNOWN_MALICIOUS_ACCOUNTS)} malicious accounts.")
    except Exception as e:
        logging.error(f"Error obtaining malicious accounts: {e}")

def detect_funding(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global KNOWN_MALICIOUS_ACCOUNTS

    findings = []

    from_ = transaction_event.transaction.from_.lower()
    if transaction_event.transaction.value > 0 and from_ in KNOWN_MALICIOUS_ACCOUNTS.keys():
        findings.append(MaliciousAccountFundingFinding.funding(transaction_event.transaction.to, from_, KNOWN_MALICIOUS_ACCOUNTS[from_]))

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)


def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
    logging.info(f"Handling block {block_event.block_number}.")
    global KNOWN_MALICIOUS_ACCOUNTS
    if len(KNOWN_MALICIOUS_ACCOUNTS) == 0 or block_event.block_number % 240 == 0:
        logging.info(f"Updating known malicious accounts at block {block_event.block_number}.")
        update_known_malicious_accounts(web3.eth.chain_id)

    findings = []
    return findings
