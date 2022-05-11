import logging
import sys
import threading
from datetime import datetime, timedelta

import forta_agent
import pandas as pd
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3

from src.constants import (ADDRESS_QUEUE_SIZE, AGENT_IDS,
                           ALERT_ID_STAGE_MAPPING,
                           DATE_LOOKBACK_WINDOW_IN_DAYS)
from src.findings import AlertCombinerFinding
from src.forta_explorer import FortaExplorer

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
forta_explorer = FortaExplorer()

FINDINGS_CACHE = []
ALERTED_ADDRESSES = []
MUTEX = False

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global ALERTED_ADDRESSES
    ALERTED_ADDRESSES = []

    global FINDINGS_CACHE
    FINDINGS_CACHE = []

    global MUTEX
    MUTEX = False


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')


def detect_attack(w3, forta_explorer, block_event: forta_agent.block_event.BlockEvent):
    """
    this function returns finding for any address for which alerts in 4 stages were observed in a given time window
    :return: findings: list
    """
    global ALERTED_ADDRESSES
    global MUTEX

    if not MUTEX:
        MUTEX = True

        # get time for block to derive date range for query
        end_date = datetime.utcfromtimestamp(block_event.block.timestamp)
        start_date = end_date - timedelta(days=DATE_LOOKBACK_WINDOW_IN_DAYS)
        logging.info(f"Analyzing alerts from {start_date} to {end_date}")

        # get all alerts for date range
        df_forta_alerts = forta_explorer.empty_alerts()
        for agent_id in AGENT_IDS:
            agent_alerts = forta_explorer.alerts_by_agent(agent_id, start_date, end_date)
            df_forta_alerts = pd.concat([df_forta_alerts, agent_alerts])
            logging.info(f"Fetched {len(agent_alerts)} for agent {agent_id}")

        # get all addresses that were part of the alerts
        # to optimize, we only check money laundering addresses as this is required to fullfill all 4 stage requirements
        money_laundering = df_forta_alerts[df_forta_alerts["alertId"] == "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH"]

        addresses = set()
        for index, row in money_laundering.iterrows():
            addresses = addresses.union(set(row['addresses']))

        # analyze each address' alerts
        for potential_attacker_address in addresses:
            logging.debug(potential_attacker_address)
            # if address is a contract or null address, skip
            if(is_contract(w3, potential_attacker_address) or potential_attacker_address.startswith('0x0000000000')):
                continue

            # map each alert to 4 stages
            stages = set()
            involved_addresses = set()
            address_alerts = df_forta_alerts[df_forta_alerts["addresses"].apply(lambda x: potential_attacker_address in x)]
            involved_alert_ids = address_alerts["alertId"].unique()
            for alert_id in involved_alert_ids:
                if alert_id in ALERT_ID_STAGE_MAPPING.keys():
                    stage = ALERT_ID_STAGE_MAPPING[alert_id]
                    stages.add(stage)
                    # get addresses from address field to add to involved_addresses
                    address_alerts[address_alerts["alertId"] == alert_id]["addresses"].apply(lambda x: involved_addresses.update(set(x)))

            logging.info(f"Address {potential_attacker_address} stages: {stages}")

            # if all 4 stages are observed, update the address alerted list and add a finding
            if len(stages) == 4 and potential_attacker_address not in ALERTED_ADDRESSES:
                update_alerted_addresses(w3, potential_attacker_address)
                FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(potential_attacker_address, start_date, end_date, involved_addresses, involved_alert_ids))
                logging.info(f"Findings count {len(FINDINGS_CACHE)}")

        MUTEX = False


def update_alerted_addresses(w3, address: str):
    """
    this function maintains a list addresses; holds up to ADDRESS_QUEUE_SIZE in memory
    :return: None
    """
    global ALERTED_ADDRESSES

    ALERTED_ADDRESSES.append(Web3.toChecksumAddress(address))
    if len(ALERTED_ADDRESSES) > ADDRESS_QUEUE_SIZE:
        ALERTED_ADDRESSES.pop(0)


def provide_handle_block(w3, forta_explorer):
    logging.debug("provide_handle_block called")

    def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        logging.debug("handle_block with w3 called")
        global FINDINGS_CACHE
        global MUTEX

        if not MUTEX:
            thread = threading.Thread(target=detect_attack, args=(w3, forta_explorer, block_event))
            thread.start()

        # uncomment for local testing; otherwise the process will exit
        # while (thread.is_alive()):
        #     pass
        findings = FINDINGS_CACHE
        FINDINGS_CACHE = []
        return findings

    return handle_block


real_handle_block = provide_handle_block(web3, forta_explorer)


def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)
