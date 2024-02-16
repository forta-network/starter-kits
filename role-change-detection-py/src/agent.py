import logging
import sys

from forta_agent import get_json_rpc_url, Web3, Finding, FindingSeverity, FindingType, EntityType
from hexbytes import HexBytes
from functools import lru_cache
from src.constants import *
from src.blockexplorer import *


# Initialize web3
web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# Replace with blockexplorer instance
blockexplorer = BlockExplorer(web3.eth.chain_id)

# Logging set up.
root = logging.getLogger()
root.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

DENOMINATOR_COUNT = 0
ALERT_COUNT = 0

def initialize():
    """
    Initialize variables for anomaly score.
    """
    global DENOMINATOR_COUNT
    DENOMINATOR_COUNT = 0

    global ALERT_COUNT
    ALERT_COUNT = 0


@lru_cache(maxsize=128000)
def is_contract(w3, address):
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')


def detect_role_change(w3, blockexplorer, transaction_event):
    """
    search transaction input when to is a contract for key words indicating a function call triggering a role change
    :return: detect_role_change: Finding
    """
    global DENOMINATOR_COUNT
    global ALERT_COUNT

    findings = []

    if transaction_event.to is None:
        return findings

    if is_contract(w3, transaction_event.to):
        DENOMINATOR_COUNT += 1
        try:
            abi = blockexplorer.get_abi(transaction_event.to)
            if abi == None:
                logging.warning(f"Unable to retrieve ABI for {transaction_event.to}")
                return findings
        except Exception:
            logging.warning(f"Unable to retrieve ABI for {transaction_event.to}")
            return findings
        contract = w3.eth.contract(address=Web3.toChecksumAddress(transaction_event.to), abi=abi)
        try:
            transaction_data = contract.decode_function_input(transaction_event.transaction.data)
            function_call = str(transaction_data[0])[10:-1]
        except Exception as e:
            logging.warning(f"Failed to decode tx input: {e}")
            return findings
        matching_keywords = []
        for keyword in ROLE_CHANGE_KEYWORDS:
            if keyword in function_call.lower():
                matching_keywords.append(keyword)
        if len(matching_keywords) > 0:
            ALERT_COUNT += 1
            findings.append(Finding(
                {
                    "name": "Possible Role Change",
                    "description": f"Possible role change affecting {transaction_event.to}",
                    "alert_id": "ROLE-CHANGE",
                    "type": FindingType.Suspicious,
                    "severity": FindingSeverity.Medium,
                    "metadata": {
                        "matching keywords": matching_keywords,
                        "function signature": str(transaction_data[0])[10:-1],
                        "anomaly_score": (1.0 * ALERT_COUNT) / DENOMINATOR_COUNT
                    },
                    "labels": [
                        {
                            "entity_type": EntityType.Address,
                            "entity": transaction_event.to,
                            "label": "victim",
                            "confidence": 0.3
                        },
                        {
                            "entity_type": EntityType.Address,
                            "entity": transaction_event.from_,
                            "label": "attacker",
                            "confidence": 0.3
                        },
                        {
                            "entity_type": EntityType.Transaction,
                            "entity": transaction_event.transaction.hash,
                            "label": "role-transfer",
                            "confidence": 0.7
                        },
                    ]
                }
            ))

    return findings


def provide_handle_transaction(w3, blockexplorer):
    def handle_transaction(transaction_event):
        return detect_role_change(w3, blockexplorer, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3, blockexplorer)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
