from functools import lru_cache
from timeit import default_timer as timer
from random import randint

import backoff
import requests
from cachetools import cached, TTLCache

from src.utils.constants import (
    ETHPLORER_ENDPOINT,
    ETHERSCAN_ENDPOINT,
    CHAIN_ID_METADATA_MAPPING,
    LUABASE_SUPPORTED_CHAINS,
)
from src.utils.luabase_constants import (
    LUABASE_API_KEY,
    LUABASE_URL,
    ANOMALY_SCORE_QUERY_ID,
    ALERT_COUNT_QUERY_ID,
    BOT_ID,
)
from src.utils.keys import ETHPLORER_KEY, ETHERSCAN_KEYS
from src.utils.logger import logger


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


# cache anomaly scores for no longer than 30 minutes
@cached(cache=TTLCache(maxsize=10, ttl=1800))
def get_anomaly_score(chain_id):
    anomaly_score = 0
    alert_count = 0
    (
        chain_name,
        default_alert_count,
        default_token_transfer_count,
    ) = CHAIN_ID_METADATA_MAPPING[chain_id]
    if chain_id in LUABASE_SUPPORTED_CHAINS:
        result = luabase_request(chain_name, BOT_ID, ANOMALY_SCORE_QUERY_ID)
        if result is not None:
            anomaly_score = round(result["anomaly_score"], 6)

    if anomaly_score == 0:
        result = luabase_request(chain_name, BOT_ID, ALERT_COUNT_QUERY_ID)
        if result is not None:
            alert_count = round(result["alert_count"], 3)
        alert_count = alert_count if alert_count > 0 else default_alert_count
        anomaly_score = round(alert_count / default_token_transfer_count, 6)

    return anomaly_score
