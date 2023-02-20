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
from web3 import Web3

from src.findings import NegativeReputationFinding
from src.constants import (BASE_BOTS, CACHE_VERSION)

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

CHAIN_ID = 1

DATABASE = f"https://research.forta.network/database/bot/{web3.eth.chain_id}"
BOT_ID_TO_SOURCE_MAPPING = {}

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

    global BOT_ID_TO_SOURCE_MAPPING
    global CHAIN_ID
    try:
        CHAIN_ID = web3.eth.chain_id
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e

    subscription_json = []
    for botId, alertId, source in BASE_BOTS:
        subscription_json.append({"botId": botId, "alertId": alertId})
        BOT_ID_TO_SOURCE_MAPPING[botId] = source

    return {"alertConfig": {"subscriptions": subscription_json}}


def process_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global CHAIN_ID
    global BOT_ID_TO_SOURCE_MAPPING
    findings = []
    start = time.time()

    chain_id = int(alert_event.alert.source.block.chain_id) if alert_event.alert.source.block.chain_id is not None else int(alert_event.chain_id)
    if chain_id == CHAIN_ID:
        logging.info(f"alert {alert_event.alert_hash} received for proper chain {chain_id}")

        source = BOT_ID_TO_SOURCE_MAPPING[alert_event.bot_id]
        if source == "Forta Foundation":
            attacker_addresses_lower = parse_indictors_forta_foundation(alert_event.alert.description)
            findings.append(NegativeReputationFinding.create_finding(attacker_addresses_lower, alert_event, source))
        else:
            attacker_addresses_lower = parse_indictors_scam_sniffer(alert_event.alert.description)
            findings.append(NegativeReputationFinding.create_finding(attacker_addresses_lower, alert_event, source))
    else:
        logging.debug(f"alert {alert_event.alert_hash} received for incorrect chain {alert_event.chain_id}. This bot is for chain {CHAIN_ID}.")

    end = time.time()
    logging.info(f"alert {alert_event.alert_hash} processing took {end - start} seconds")

    return findings


def parse_indictors_forta_foundation(description: str) -> set:
    #  # 0x4258ebe8ca35de27d7f60a2512015190b8ad70e7 likely involved in an attack (ATTACK-DETECTOR-ICE-PHISHING)
    attacker_address_lower = description[0:42].lower()
    attacker_addresses = set()
    attacker_addresses.add(attacker_address_lower)
    return attacker_addresses


def parse_indictors_scamsniffer(description: str) -> list:
    #  Suscipious Seaport Order detected, from: 0xff30b32c7e7da16cc7cd100a54ecd77b103d1a1c, recepients: 0xfF30b32c7E7da16CC7cD100A54ecd77b103D1A1C
    attacker_addresses = set()
    
    start = len("Suscipious Seaport Order detected, from: ")
    attacker_address_lower1 = description[start:42+start].lower()
    attacker_addresses.add(attacker_address_lower1)
    start = len("Suscipious Seaport Order detected, from: 0xff30b32c7e7da16cc7cd100a54ecd77b103d1a1c, recepients: ")
    attacker_address_lower2 = description[start:42+start].lower()
    attacker_addresses.add(attacker_address_lower2)
    return attacker_addresses


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
    return


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
