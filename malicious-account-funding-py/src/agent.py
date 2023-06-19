from datetime import datetime
import logging
import sys
from os import environ

from expiring_dict import ExpiringDict
from functools import lru_cache
import forta_agent
from forta_agent import get_json_rpc_url
import requests
from web3 import Web3

from src.findings import MaliciousAccountFundingFinding
from src.keys import BOT_ID
from src.storage import get_secrets

SECRETS_JSON = get_secrets()


web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)


CHAIN_SOURCE_IDS_MAPPING = {
    1: ["etherscan", "etherscan-tags"],  # Ethereum
    137: ["polygon-tags"],  # Polygon
    250: ["fantom-tags"],  # Fantom
}


def initialize():
    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


@lru_cache(maxsize=1_000_000)
def is_malicious_account(chain_id: int, address: str) -> str:
    source_ids = CHAIN_SOURCE_IDS_MAPPING[chain_id]
    wallet_tag = None

    for source_id in source_ids:
        labels_url = f"https://api.forta.network/labels/state?entities={address}&sourceIds={source_id}&labels=*xploit*,*hish*,*heist*&limit=1"
        try:
            result = requests.get(labels_url).json()
            if isinstance(result["events"], list) and len(result["events"]) == 1:
                wallet_tag = result["events"][0]["label"]["label"]
        except Exception as err:
            logging.error(f"Error obtaining malicious accounts: {err}")

    return wallet_tag



def alert_count(chain_id) -> int:
    alert_stats_url = (
        f"https://api.forta.network/stats/bot/{BOT_ID}/alerts?chainId={chain_id}"
    )
    alert_count = 0
    try:
        result = requests.get(alert_stats_url).json()
        alert_count = result["total"]["count"]
    except Exception as err:
        logging.error(f"Error obtaining alert counts: {err}")

    return alert_count


def detect_funding(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    findings = []

    from_ = transaction_event.transaction.from_.lower()
    malicious_account = is_malicious_account(w3.eth.chain_id, from_)

    if transaction_event.transaction.value > 0 and malicious_account is not None:
        findings.append(
            MaliciousAccountFundingFinding.funding(
                transaction_event.hash,
                transaction_event.transaction.to,
                from_,
                malicious_account,
                CHAIN_ID
            )
        )

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(
        transaction_event: forta_agent.transaction_event.TransactionEvent,
    ) -> list:
        return detect_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
