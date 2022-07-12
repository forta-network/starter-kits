from datetime import datetime, timezone
from functools import lru_cache
from timeit import default_timer as timer

import requests

from .constants import ETHPLORER_KEY, ETHPLORER_ENDPOINT, LUABASE_ENDPOINT
from .logger import logger

@lru_cache(maxsize=1_000_000)
def get_first_tx_timestamp(address) -> int:
    '''Gets address's first tx timestamp from Luabase in unix.'''
    payload = {
        "uuid": "BACON",
        "parameters": {
            "address": {
                "key": "address",
                "type": "value",
                "value": f"{address}"
            }
        }
    }

    first_tx_timestamp = -1
    data = {}
    try:
        r = requests.request("POST", LUABASE_ENDPOINT, json=payload)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.RequestException or Exception as err:
        logger.warn(f"Request failed for addr: {address}, err: {err}")

    if "data" in data and len(data["data"]) > 0:
        first_tx_timestamp = data["data"][0]["first_tx_timestamp"]
        first_tx_timestamp = datetime.fromisoformat(first_tx_timestamp).replace(tzinfo=timezone.utc).timestamp()


    return first_tx_timestamp

def get_account_age(address, recent_tx_timestamp) -> float:
    '''Return difference between first and recent transaction timestamp in minutes.'''
    first_tx_timestamp = get_first_tx_timestamp(address)
    logger.info(f"get_first_tx_timestamp: {get_first_tx_timestamp.cache_info()}")

    if first_tx_timestamp == -1:
        return -1
    return (recent_tx_timestamp - first_tx_timestamp) / 60

@lru_cache(maxsize=1_000_000)
def get_token_info(token_address) -> tuple:
    '''Get token name, symbol, and decimals from Ethplorer API.'''
    token_info_endpoint = f"{ETHPLORER_ENDPOINT}/getTokenInfo/{token_address}?apiKey={ETHPLORER_KEY}"
    data = {}
    try:
        r = requests.get(token_info_endpoint)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.RequestException or Exception as err:
        logger.warn(f"Request failed for token: {token_address}, err: {err}")

    name = data.get('name', 'NO_NAME')
    symbol = data.get('symbol', 'NO_SYMBOL')
    decimals = data.get('decimals', 'NO_DECIMALS')

    return name, symbol, decimals

def get_features(from_address, tx_timestamp, transfer_events) -> tuple:
    start = timer()
    features = {}

    features['transfer_counts'] = len(transfer_events)
    features['account_age_in_minutes'] = get_account_age(from_address, tx_timestamp)

    token_types = set()
    max_token_transfers_name = ''
    max_token_transfers_count = 0
    max_token_transfers_value = 0

    for transfer in transfer_events:
        token_address = transfer['address']
        value = transfer['args']['value']
        token_name, token_symbol, decimals = get_token_info(token_address)
        logger.info(f"get_token_info: {get_token_info.cache_info()}")
        token_transfers = f'{token_symbol}_transfers'
        token_value = f'{token_symbol}_value'
        if decimals != 'NO_DECIMALS': # token is likely not an erc20
            normalized_value = round(value / (10 ** int(decimals)), 3)
            features[token_transfers] = features.get(token_transfers, 0) + 1
            features[token_value] = features.get(token_value, 0) + normalized_value
            token_types.add(f"{token_name}-{token_symbol}")

            if features[token_transfers] > max_token_transfers_count:
                max_token_transfers_name = token_name
                max_token_transfers_count = features[token_transfers]
                max_token_transfers_value = features[token_value]

    features['token_types'] = sorted(list(token_types))
    features['max_single_token_transfers_name'] = max_token_transfers_name

    features['tokens_type_counts'] = len(token_types)
    features['max_single_token_transfers'] = max_token_transfers_count
    features['max_single_token_transfers_value'] = max_token_transfers_value

    valid = valid_features(features)

    end = timer()
    features['feature_generation_response_time'] = end - start

    return valid, features

def valid_features(features) -> bool:
    '''Evaluate model input values'''
    if features['account_age_in_minutes'] < 0:
        return False

    return True
