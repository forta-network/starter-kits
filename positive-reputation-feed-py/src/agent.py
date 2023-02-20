# Copyright 2022 The Forta Foundation

import logging
import sys
from datetime import datetime

import forta_agent
import time
import pickle
import os
import requests
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3

from src.findings import PositiveReputationFinding
from src.constants import (BASE_BOTS, ADDRESS_TO_SOURCE_BOT_MAPPING_KEY, CONTRACT_CACHE_KEY, CONTRACT_CACHE_MAX_QUEUE_SIZE, CACHE_VERSION)

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

CHAIN_ID = 1
ADDRESS_TO_SOURCE_BOT_MAPPING = {}  # address -> [source_bot_1, source_bot_2, ...]
CONTRACT_CACHE = dict()  # address -> is_contract
BOT_ID_TO_SOURCE_MAPPING = dict()

DATABASE = f"https://research.forta.network/database/bot/{web3.eth.chain_id}"

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    logging.debug('initializing')

    global CHAIN_ID
    global BOT_ID_TO_SOURCE_MAPPING
    try:
        CHAIN_ID = web3.eth.chain_id
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e

    global ADDRESS_TO_SOURCE_BOT_MAPPING
    address_to_source_bot_mapping = load(ADDRESS_TO_SOURCE_BOT_MAPPING_KEY)
    ADDRESS_TO_SOURCE_BOT_MAPPING = {} if address_to_source_bot_mapping is None else address_to_source_bot_mapping
    logging.info(f"Loaded {len(ADDRESS_TO_SOURCE_BOT_MAPPING)} entries to address to source bot mapping data structure.")

    global CONTRACT_CACHE
    contract_cache = load(CONTRACT_CACHE_KEY)
    CONTRACT_CACHE = [] if contract_cache is None else contract_cache
    logging.info(f"Loaded {len(CONTRACT_CACHE)} entries to contract cache.")

    subscription_json = []
    for bot, alertId, source in BASE_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId})
        BOT_ID_TO_SOURCE_MAPPING[bot] = source

    return {"alertConfig": {"subscriptions": subscription_json}}


def is_contract(w3, addresses) -> bool:
    """
    this function determines whether address/ addresses is a contract; if all are contracts, returns true; otherwise false
    :return: is_contract: bool
    """
    global CONTRACT_CACHE

    if addresses is None:
        return True

    if CONTRACT_CACHE.get(addresses) is not None:
        return CONTRACT_CACHE[addresses]
    else:
        is_contract = True
        for address in addresses.split(','):
            try:
                code = w3.eth.get_code(Web3.toChecksumAddress(address))
            except Exception as e:
                logging.error(f"Exception in is_contract {e}")
            is_contract = is_contract & (code != HexBytes('0x'))
        CONTRACT_CACHE[addresses] = is_contract

        if len(CONTRACT_CACHE) > CONTRACT_CACHE_MAX_QUEUE_SIZE:
            CONTRACT_CACHE.popitem(last=False)

        return is_contract


def is_address(w3, addresses: str) -> bool:
    """
    this function determines whether address is a valid address
    :return: is_address: bool
    """
    if addresses is None:
        return True

    is_address = True
    for address in addresses.split(','):
        for c in ['a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
            test_str = c + c + c + c + c + c + c + c + c  # make a string of length 9; I know this is ugly, but regex didnt work
            if test_str in address.lower():
                is_address = False

    return is_address


def process_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global CHAIN_ID
    findings = []
    start = time.time()

    chain_id = int(alert_event.alert.source.block.chain_id) if alert_event.alert.source.block.chain_id is not None else int(alert_event.chain_id)
    if chain_id == CHAIN_ID:
        logging.info(f"alert {alert_event.alert_hash} received for proper chain {chain_id}")

        address_lower = alert_event.alert.description[0:42].lower()
        if address_lower not in ADDRESS_TO_SOURCE_BOT_MAPPING.keys():
            ADDRESS_TO_SOURCE_BOT_MAPPING[address_lower] = [alert_event.alert.source.bot.id]
        else:
            ADDRESS_TO_SOURCE_BOT_MAPPING[address_lower].append(alert_event.alert.source.bot.id)

        source = BOT_ID_TO_SOURCE_MAPPING[alert_event.alert.source.bot.id]

        findings.append(PositiveReputationFinding.create_finding(address_lower, ADDRESS_TO_SOURCE_BOT_MAPPING[address_lower], source))
    else:
        logging.debug(f"alert {alert_event.alert_hash} received for incorrect chain {alert_event.chain_id}. This bot is for chain {CHAIN_ID}.")

    end = time.time()
    logging.info(f"alert {alert_event.alert_hash} processing took {end - start} seconds")

    return findings


def persist(obj: object, key: str):
    global CACHE_VERSION
    try:
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"Persisting {CACHE_VERSION}-{key} using API")
            bytes = pickle.dumps(obj)
            token = forta_agent.fetch_jwt({})

            headers = {"Authorization": f"Bearer {token}"}
            res = requests.post(f"{DATABASE}{CACHE_VERSION}-{key}", data=bytes, headers=headers)
            logging.info(f"Persisting {CACHE_VERSION}-{key} to database. Response: {res}")
            return
        else:
            logging.info(f"Persisting {CACHE_VERSION}-{key} locally")
            pickle.dump(obj, open(CACHE_VERSION + '-' + key, "wb"))
    except Exception as e:
        logging.warning(f"Error persisting {CACHE_VERSION}-{key}: {e}")


def load(key: str) -> object:
    try:
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"Loading {CACHE_VERSION}-{key} using API")
            token = forta_agent.fetch_jwt({})
            headers = {"Authorization": f"Bearer {token}"}
            res = requests.get(f"{DATABASE}{CACHE_VERSION}-{key}", headers=headers)
            logging.info(f"Loaded {CACHE_VERSION}-{key}. Response: {res}")
            if res.status_code == 200 and len(res.content) > 0:
                return pickle.loads(res.content)
            else:
                logging.info(f"{CACHE_VERSION}-{key} does not exist")
        else:
            # load locally
            logging.info(f"Loading {CACHE_VERSION}-{key} locally")
            if os.path.exists(CACHE_VERSION + '-' + key):
                return pickle.load(open(CACHE_VERSION + '-' + key, "rb"))
            else:
                logging.info(f"File {CACHE_VERSION}-{key} does not exist")
        return None
    except Exception as e:
        logging.warning(f"Error loading {CACHE_VERSION}-{key}: {e}")
        return None


def persist_state():
    global CONTRACT_CACHE
    persist(CONTRACT_CACHE, CONTRACT_CACHE_KEY)

    global ADDRESS_TO_SOURCE_BOT_MAPPING
    persist(ADDRESS_TO_SOURCE_BOT_MAPPING, ADDRESS_TO_SOURCE_BOT_MAPPING_KEY)


def provide_handle_alert(w3):
    logging.debug("provide_handle_alert called")

    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        logging.debug("handle_alert inner called")

        findings = process_alert(alert_event)
        return findings

    return handle_alert


real_handle_alert = provide_handle_alert(web3)


def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    logging.debug("handle_alert called")
    return real_handle_alert(alert_event)


def handle_block(block_event: forta_agent.BlockEvent):
    logging.debug("handle_block called")

    if datetime.now().minute == 0:  # every hour
        persist_state()

    return []
