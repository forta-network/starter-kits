import asyncio
import logging
import sys

from forta_bot import scan_ethereum, scan_optimism, scan_polygon, scan_arbitrum, TransactionEvent, get_chain_id, run_health_check, Finding, FindingSeverity, FindingType, EntityType
from web3 import Web3, AsyncWeb3
from hexbytes import HexBytes
from async_lru import alru_cache
from constants import *
from blockexplorer import *

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


@alru_cache(maxsize=128000)
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

    if transaction_event.to is None:
        return findings

    if await is_contract(w3, transaction_event.to):
        DENOMINATOR_COUNT += 1
        try:
            abi = await blockexplorer.get_abi(transaction_event.to)
            if abi == None:
                logging.warning(f"Unable to retrieve ABI for {transaction_event.to}")
                return findings
        except Exception:
            logging.warning(f"Unable to retrieve ABI for {transaction_event.to}")
            return findings
        contract = w3.eth.contract(address=Web3.to_checksum_address(transaction_event.to), abi=abi)
        try:
            transaction_data = contract.decode_function_input(transaction_event.transaction.data)
            function_call = str(transaction_data[0])[10:-1]
        except Exception as e:
            logging.warning(f"Failed to decode tx input: {e}")
            return findings
        matching_keywords = [
                keyword for keyword in ROLE_CHANGE_KEYWORDS
                if keyword in function_call.lower() and not (keyword == 'own' and 'down' in function_call.lower())
            ]
        if len(matching_keywords) > 0:
            function_params = transaction_data[1]
            addresses_in_function_params = [
                function_params[keyword].lower() for keyword in FUNCTION_PARAMETER_KEYWORDS
                if keyword in function_params and str(function_params[keyword]).startswith('0x')
            ]
            ALERT_COUNT += 1
            print(type(matching_keywords))
            findings.append(Finding(
                {
                    "name": "Possible Role Change",
                    "description": f"Possible role change affecting {transaction_event.to}",
                    "alert_id": "ROLE-CHANGE",
                    "type": FindingType.Suspicious,
                    "severity": FindingSeverity.Medium,
                    "metadata": {
                        "matching keywords": ', '.join(matching_keywords),
                        "function signature": str(transaction_data[0])[10:-1],
                        "anomaly_score": str((1.0 * ALERT_COUNT) / DENOMINATOR_COUNT)
                    },
                    'source': {
                        'chains': [{'chainId': get_chain_id()}],
                        'transactions': [{'chainId': get_chain_id(), 'hash': transaction_event.hash}]
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
                        *[
                            {
                                "entity_type": EntityType.Address,
                                "entity": address,
                                "label": "attacker",
                                "confidence": 0.3
                            } for address in addresses_in_function_params
                        ],
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
            'rpc_key_id': "420b57cc-c2cc-442c-8fd8-901d70a835a5",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        scan_optimism({
            'rpc_url': "https://opt-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "67374ee9-1b70-485d-be75-83589aa0e10d",
            'local_rpc_url': "10",
            'handle_transaction': handle_transaction
        }),
        scan_polygon({
            'rpc_url': "https://polygon-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "7e311823-448b-41fa-b530-2029b7db21fa",
            'local_rpc_url': "137",
            'handle_transaction': handle_transaction
        }),
        scan_arbitrum({
            'rpc_url': "https://arb-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "fc84b32c-ff10-4eb2-b5d6-70062ea39fa6",
            'local_rpc_url': "42161",
            'handle_transaction': handle_transaction
        }),
        run_health_check()
    )

if __name__ == "__main__":
    asyncio.run(main())