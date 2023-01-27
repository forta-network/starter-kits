from functools import lru_cache
from timeit import default_timer as timer
from random import randint

import backoff
import requests
from expiring_dict import ExpiringDict

from src.utils.constants import (
    ETHPLORER_ENDPOINT,
    ETHERSCAN_ENDPOINT,
)

from src.utils.keys import ETHPLORER_KEY, ETHERSCAN_KEYS
from src.utils.logger import logger

GLOBAL_TOTAL_TX_COUNTER = ExpiringDict(ttl=86_400)
BOT_ID = "0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8"

# Retry if etherscan api response status is not ok = 0.
@backoff.on_predicate(
    backoff.expo,
    lambda x: int(x.json().get("status", 0)) == 0,
    max_tries=3,
    jitter=None,
)
def get_first_tx(url):
    return requests.get(url)


@backoff.on_exception(
    backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=None
)
def get_token_data(url):
    return requests.get(url)


@lru_cache(maxsize=1_000_000)
def get_first_tx_timestamp(address) -> int:
    """Gets address's first tx timestamp from Etherscan in unix."""
    first_tx_timestamp = -1
    data = {}
    api_key = ETHERSCAN_KEYS[randint(0, 1)]
    addr_first_tx_endpoint = f"{ETHERSCAN_ENDPOINT}&address={address}&apikey={api_key}"
    try:
        r = get_first_tx(addr_first_tx_endpoint)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.RequestException or Exception as err:
        logger.warn(f"Request failed for addr: {address}, err: {err}")

    if int(data["status"]) == 1:
        first_tx_timestamp = int(data["result"][0]["timeStamp"])
    else:
        first_tx_timestamp = data["result"]

    return first_tx_timestamp


def get_account_active_period(address, recent_tx_timestamp) -> float:
    """Return difference between first and recent transaction timestamp in minutes."""
    first_tx_timestamp = get_first_tx_timestamp(address)
    logger.info(f"get_first_tx_timestamp: {get_first_tx_timestamp.cache_info()}")

    if isinstance(first_tx_timestamp, str):
        return first_tx_timestamp

    return (recent_tx_timestamp - first_tx_timestamp) / 60


@lru_cache(maxsize=1_000_000)
def get_token_info(token_address) -> tuple:
    """Get token name, symbol, and decimals from Ethplorer API."""
    token_info_endpoint = (
        f"{ETHPLORER_ENDPOINT}/getTokenInfo/{token_address}?apiKey={ETHPLORER_KEY}"
    )
    data = {}
    try:
        r = get_token_data(token_info_endpoint)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.RequestException or Exception as err:
        logger.warn(f"Request failed for token: {token_address}, err: {err}")

    name = data.get("name", "NO_NAME")
    symbol = data.get("symbol", "NO_SYMBOL")
    decimals = data.get("decimals", "NO_DECIMALS")

    return name, symbol, decimals


def get_features(from_address, tx_timestamp, transfer_events) -> tuple:
    start = timer()
    features = {}

    features["transfer_counts"] = len(transfer_events)
    features["account_active_period_in_minutes"] = get_account_active_period(
        from_address, tx_timestamp
    )

    token_types = set()
    max_token_transfers_name = ""
    max_single_token_transfers_count = 0
    max_single_token_transfers_value = 0

    for transfer in transfer_events:
        token_address = transfer["address"]
        value = transfer["args"]["value"]
        token_name, token_symbol, decimals = get_token_info(token_address)
        logger.info(f"get_token_info: {get_token_info.cache_info()}")
        token_transfers = f"{token_symbol}_transfers"
        token_value = f"{token_symbol}_value"
        if decimals != "NO_DECIMALS":  # token is likely not an erc20
            normalized_value = round(value / (10 ** int(decimals)), 3)
            features[token_transfers] = features.get(token_transfers, 0) + 1
            features[token_value] = features.get(token_value, 0) + normalized_value
            token_types.add(f"{token_name}-{token_symbol}")

            if features[token_transfers] > max_single_token_transfers_count:
                max_token_transfers_name = token_name
                max_single_token_transfers_count = features[token_transfers]
                max_single_token_transfers_value = features[token_value]

    features["token_types"] = sorted(list(token_types))
    features["max_single_token_transfers_name"] = max_token_transfers_name

    features["tokens_type_counts"] = len(token_types)
    features["max_single_token_transfers_count"] = max_single_token_transfers_count
    features["max_single_token_transfers_value"] = max_single_token_transfers_value

    valid = valid_features(features)

    end = timer()
    features["feature_generation_response_time_sec"] = end - start

    return valid, features


def valid_features(features) -> bool:
    """Evaluate model input values"""
    if isinstance(features["account_active_period_in_minutes"], str):
        return False

    return True


def luabase_request(chain_name, bot_id, query_uuid):
    headers = {"content-type": "application/json"}
    payload = {
        "api_key": LUABASE_API_KEY,
        "block": {
            "data_uuid": query_uuid,
            "details": {
                "parameters": {
                    "chain": {"type": "value", "value": chain_name},
                    "bot_id": {"type": "value", "value": bot_id},
                }
            },
        },
    }
    data = None
    try:
        response = requests.request("POST", LUABASE_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()["data"][0]
    except requests.exceptions.HTTPError as err:
        logger.info(f"Luabase error: {err}")
    return data


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
        alert_count = result["alertIds"]["ANOMALOUS-TOKEN-TRANSFERS-TX"]["count"]
    except Exception as err:
        logger.error(f"Error obtaining alert counts: {err}")

    return alert_count


def get_anomaly_score(chain_id: int) -> float:
    total_alerts = alert_count(chain_id)
    total_tx_count = sum(GLOBAL_TOTAL_TX_COUNTER.values())
    return total_alerts / total_tx_count
