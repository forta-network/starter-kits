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
    try:
        CHAIN_ID = web3.eth.chain_id
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e

    subscription_json = []
    for bot, alertId, address_information in BASE_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId, "chainId": CHAIN_ID})

    alert_config = {"alertConfig": {"subscriptions": subscription_json}}
    print(alert_config)
    return alert_config


def process_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global CHAIN_ID
    findings = []
    start = time.time()

    chain_id = int(alert_event.alert.source.block.chain_id) if alert_event.alert.source.block.chain_id is not None else int(alert_event.chain_id)
    if chain_id == CHAIN_ID:
        logging.info(f"alert {alert_event.alert_hash} received for proper chain {chain_id}")

        attacker_address_lower, victim_address_lower, victim_name = parse_indictors(alert_event.alert.description)

        findings.append(NegativeReputationFinding.create_finding(attacker_address_lower, victim_address_lower, victim_name, alert_event))
    else:
        logging.debug(f"alert {alert_event.alert_hash} received for incorrect chain {alert_event.chain_id}. This bot is for chain {CHAIN_ID}.")

    end = time.time()
    logging.info(f"alert {alert_event.alert_hash} processing took {end - start} seconds")

    return findings


def parse_indictors(description: str) -> tuple:
    #  either:
    #  {attacker_address} likely involved in an attack ({alert_id}).
    #  {attacker_address} likely involved in an attack ({alert_id} on {victim_address} ({victim_name}))
    attacker_address_lower = description[0:42].lower()
    victim_address_lower = ""
    victim_name = ""
    if "))" in description:
        tokens = description.split(" ")
        victim_address_lower = tokens[8].lower()
        victim_name = tokens[9]
        for i in range(10, len(tokens)):
            victim_name += " " + tokens[i]
        victim_name = victim_name.strip("()")

    return (attacker_address_lower, victim_address_lower, victim_name)


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

        findings = process_alert(w3, alert_event)
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
