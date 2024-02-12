import asyncio
import logging
import sys

# from forta_agent import get_json_rpc_url, Web3, Finding, FindingSeverity, FindingType, EntityType
from forta_bot import scan_ethereum, scan_base, TransactionEvent, get_chain_id, run_health_check, Finding, FindingSeverity, FindingType, EntityType
from web3 import Web3, AsyncWeb3
from hexbytes import HexBytes
from constants import *
from blockexplorer import *


# Initialize web3
# web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# Replace with blockexplorer instance
blockexplorer = BlockExplorer(get_chain_id())

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

async def initialize():
    """
    Initialize variables for anomaly score.
    """
    global DENOMINATOR_COUNT
    DENOMINATOR_COUNT = 0

    global ALERT_COUNT
    ALERT_COUNT = 0

    await blockexplorer.set_api_key()


async def is_contract(w3, address):
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = await w3.eth.get_code(Web3.to_checksum_address(address))
    return code != HexBytes('0x')


async def detect_role_change(w3, blockexplorer, transaction_event):
    """
    search transaction input when to is a contract for key words indicating a function call triggering a role change
    :return: detect_role_change: Finding
    """
    global DENOMINATOR_COUNT
    global ALERT_COUNT

    findings = []

    if await is_contract(w3, transaction_event.to):
        DENOMINATOR_COUNT += 1
        try:
            abi = await blockexplorer.get_abi(transaction_event.to)
            if abi == None:
                logging.warning(f"Unable to retrieve ABI for {transaction_event.to}")
                return findings
        except Exception:
            logging.warn(f"Unable to retrieve ABI for {transaction_event.to}")
            return findings
        contract = w3.eth.contract(address=Web3.to_checksum_address(transaction_event.to), abi=abi)
        transaction = await w3.eth.get_transaction(transaction_event.hash)
        print(f"transaction: {transaction}")
        try:
            transaction_data = contract.decode_function_input(transaction.input)
            print(f"transaction_data: {transaction_data}")
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
                        "anomaly_score": str((1.0 * ALERT_COUNT) / DENOMINATOR_COUNT)
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


async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider):
    return await detect_role_change(web3, blockexplorer, transaction_event)

async def main():
    await initialize()
    
    await asyncio.gather(
        scan_ethereum({
            'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "e698634d-79c2-44fe-adf8-f7dac20dd33c",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        # NOTE: Currently don't have BaseScan API
        # scan_base({
        #     'rpc_url': "https://base-mainnet.g.alchemy.com/v2",
        #     'rpc_key_id': "1d3097d9-6e44-4ca7-a61b-2209a85d262f",
        #     'local_rpc_url': "8453",
        #     'handle_transaction': handle_transaction
        # }),
        run_health_check()
    )

if __name__ == "__main__":
    asyncio.run(main())