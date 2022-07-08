from collections import namedtuple
from functools import lru_cache


from forta_agent import Finding, FindingType, FindingSeverity, get_web3_provider
import requests

ERC20_TRANSFER_EVENT = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}'

MODEL_FEATURES = [
    'APE_transfers',
    'APE_value',
    'CRV_transfers',
    'CRV_value',
    'DAI_transfers',
    'DAI_value',
    'GALA_transfers',
    'GALA_value',
    'HEX_transfers',
    'HEX_value',
    'KOK_transfers',
    'KOK_value',
    'LINK_transfers',
    'LINK_value',
    'LOOKS_transfers',
    'LOOKS_value',
    'MANA_transfers',
    'MANA_value',
    'MATIC_transfers',
    'MATIC_value',
    'SAITAMA_transfers',
    'SAITAMA_value',
    'SAND_transfers',
    'SAND_value',
    'SHIB_transfers',
    'SHIB_value',
    'SOS_transfers',
    'SOS_value',
    'STRNGR_transfers',
    'STRNGR_value',
    'STRONG_transfers',
    'STRONG_value',
    'USDC_transfers',
    'USDC_value',
    'USDT_transfers',
    'USDT_value',
    'WBTC_transfers',
    'WBTC_value',
    'WETH_transfers',
    'WETH_value',
    'account_age_in_minutes',
    'max_single_token_transfers',
    'max_single_token_transfers_value',
    'tokens_type_counts',
    'transfer_counts']

TOP_20_TOKENS = {
    'address': 'USDT'
}

LUABASE_ENDPOINT = "https://api.luabase.com/run"
ETHPLORER_KEY = ""
ETHPLORER_ENDPOINT = "https://api.ethplorer.io"

# TODO add logging and log errors

@lru_cache(maxsize=1_000_000)
def get_first_tx_timestamp(address) -> int:
    '''Gets address's first tx timestamp from Luabase in unix.'''
    payload = {
        "uuid": "",
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
        print(f"Request failed for addr: {address}, err: {err}")

    if "data" in data and len(data["data"]) > 0:
        first_tx_timestamp = data["data"][0]["first_tx_timestamp"]

    return first_tx_timestamp

def get_account_age(address, recent_tx_timestamp) -> float:
    '''Return difference between first and recent transaction timestamp in minutes.'''
    first_tx_timestamp = get_first_tx_timestamp(address)
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
        print(f"Request failed for token: {token_address}, err: {err}")

    name = data.get('name', 'NO_NAME')
    symbol = data.get('symbol', 'NO_SYMBOL')
    decimals = data.get('decimals', 'NO_DECIMALS')

    return name, symbol, decimals

def get_features(from_address, tx_timestamp, transfer_events) -> tuple:
    features = {}
    features_metadata = {}

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
        token_transfers = f'{token_symbol}_transfers'
        token_value = f'{token_symbol}_value'
        if decimals != 'NO_DECIMALS': # token is likely not an erc20
            normalized_value = value / (10 ** int(decimals))
            features[token_transfers] = features.get(token_transfers, 0) + 1
            features[token_value] = features.get(token_value, 0) + normalized_value
            token_types.add(f"{token_name}-{token_symbol}")

            if features[token_transfers] > max_token_transfers_count:
                max_token_transfers_name = token_name
                max_token_transfers_count = features[token_transfers]
                max_token_transfers_value = features[token_value]

    features_metadata['token_types'] = list(token_types)
    features_metadata['max_single_token_transfers_name'] = max_token_transfers_name

    features['tokens_type_counts'] = len(token_types)
    features['max_single_token_transfers'] = max_token_transfers_count
    features['max_single_token_transfers_value'] = max_token_transfers_value

    valid = valid_features(features)

    return valid, [features.get(key, 0) for key in MODEL_FEATURES], features_metadata

def valid_features(features) -> bool:
    '''Evaluate model input values'''
    if features['account_age_in_minutes'] == -1:
        return False

    return True


def handle_transaction(transaction_event):
    findings = []

    transfer_events = transaction_event.filter_log(ERC20_TRANSFER_EVENT)
    from_address = transaction_event.from_

    if len(transfer_events) > 0:
        valid_features, features, features_metadata = get_features(from_address, transaction_event.timestamp, transfer_events)
        metadata = {'from': from_address, 'model_input': features}
        metadata.update(features_metadata)

        if valid_features:
            # feed to model input
            findings.append(Finding({
                'name': 'Normal Tx with Token Transfers',
                'description': f'{from_address} executed {len(transfer_events)} token transfers',
                'alert_id': 'NORMAL-TOKEN-TRANSFERS-TX',
                'severity': FindingSeverity.Low,
                'type': FindingType.Info,
                'metadata': metadata
            }))
        else:
            # TODO output error finding
            pass


    return findings
