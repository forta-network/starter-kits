from datetime import datetime
import logging
import sys

from expiring_dict import ExpiringDict
from functools import lru_cache
import forta_agent
from forta_agent import get_json_rpc_url
import requests
from web3 import Web3

from src.findings import MaliciousAccountFundingFinding


web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)


CHAIN_SOURCE_IDS_MAPPING = {
    1: ["etherscan", "etherscan-tags"],  # Ethereum
    137: ["polygon-tags"],  # Polygon
    250: ["fantom-tags"],  # Fantom
}
GLOBAL_TOTAL_TX_COUNTER = ExpiringDict(ttl=86_400)
BOT_ID = "0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46"


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


def update_tx_counter(date_hour: str):
    # Total number of transactions in the last 24 hrs
    global GLOBAL_TOTAL_TX_COUNTER
    GLOBAL_TOTAL_TX_COUNTER[date_hour] = GLOBAL_TOTAL_TX_COUNTER.get(date_hour, 0) + 1


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


def calculate_anomaly_score(chain_id: int) -> float:
    total_alerts = alert_count(chain_id)
    total_tx_count = sum(GLOBAL_TOTAL_TX_COUNTER.values())
    return total_alerts / total_tx_count


def detect_funding(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    findings = []

    date_time = datetime.now()
    date_hour = date_time.strftime("%d/%m/%Y %H:00:00")
    update_tx_counter(date_hour)
    from_ = transaction_event.transaction.from_.lower()
    malicious_account = is_malicious_account(w3.eth.chain_id, from_)
    anomaly_score = calculate_anomaly_score(w3.eth.chain_id)

    if transaction_event.transaction.value > 0 and malicious_account is not None:
        findings.append(
            MaliciousAccountFundingFinding.funding(
                transaction_event.hash,
                transaction_event.transaction.to,
                from_,
                malicious_account,
                anomaly_score,
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
