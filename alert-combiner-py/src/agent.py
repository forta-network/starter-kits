import logging
import sys
import threading
from datetime import datetime, timedelta

import forta_agent
import pandas as pd
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3

from src.constants import (ADDRESS_QUEUE_SIZE, ALERT_ID_STAGE_MAPPING, BOT_IDS,
                           DATE_LOOKBACK_WINDOW_IN_DAYS, TX_COUNT_FILTER_THRESHOLD)
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


def is_address(w3, address: str) -> bool:
    """
    this function determines whether address is a valid address
    :return: is_address: bool
    """
    if address is None:
        return True

    for c in ['a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
        test_str = c + c + c + c + c + c + c + c + c  # make a string of length 9; I know this is ugly, but regex didnt work
        if test_str in address.lower():
            return False

    return True


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
        for bot_id in BOT_IDS:
            bot_alerts = forta_explorer.alerts_by_bot(bot_id, start_date, end_date)
            df_forta_alerts = pd.concat([df_forta_alerts, bot_alerts])
            logging.info(f"Fetched {len(bot_alerts)} for bot {bot_id}")

        # get all addresses that were part of the alerts
        # to optimize, we only check money laundering addresses as this is required to fullfill all 4 stage requirements
        money_laundering_tc = df_forta_alerts[df_forta_alerts["alertId"] == "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH"]
        txt_msg_high = df_forta_alerts[(df_forta_alerts["alertId"] == "forta-text-messages-possible-hack") & (df_forta_alerts["severity"] == "HIGH")]

        addresses = set()
        for index, row in txt_msg_high.iterrows():
            addresses = addresses.union(set(row['addresses']))

        for index, row in money_laundering_tc.iterrows():
            addresses.add(Web3.toChecksumAddress(row["description"][0:42]))  # the money laundering TC bot transaction may not be the transaction that contains the TC transfer and therefore a set of addresses unrelated, so we parse the address from the description

        # analyze each address' alerts
        for potential_attacker_address in addresses:
            logging.debug(potential_attacker_address)
            # if address is a contract or unlikely address, skip
            if(is_contract(w3, potential_attacker_address) or not is_address(w3, potential_attacker_address)):
                continue

            # map each alert to 4 stages
            stages = set()
            involved_addresses = set()
            if(len(df_forta_alerts) > 0):
                address_alerts = df_forta_alerts[df_forta_alerts["addresses"].apply(lambda x: potential_attacker_address in x if x is not None else False)]
                involved_alert_ids = address_alerts["alertId"].unique()
                for alert_id in involved_alert_ids:
                    if alert_id in ALERT_ID_STAGE_MAPPING.keys():
                        stage = ALERT_ID_STAGE_MAPPING[alert_id]
                        stages.add(stage)
                        # get addresses from address field to add to involved_addresses
                        address_alerts[address_alerts["alertId"] == alert_id]["addresses"].apply(lambda x: involved_addresses.update(set(x)))
                        logging.info(f"Found alert {alert_id} in stage {stage} for address {potential_attacker_address}")

                logging.info(f"Address {potential_attacker_address} stages: {stages}")

                # if all 4 stages are observed, update the address alerted list and add a finding
                if len(stages) == 4 and Web3.toChecksumAddress(potential_attacker_address) not in ALERTED_ADDRESSES:
                    tx_count = w3.eth.get_transaction_count(Web3.toChecksumAddress(potential_attacker_address))
                    if tx_count > TX_COUNT_FILTER_THRESHOLD:
                        logging.info(f"Address {potential_attacker_address} transacton count: {tx_count}")
                        continue
                    update_alerted_addresses(w3, potential_attacker_address)
                    FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(potential_attacker_address, start_date, end_date, involved_addresses, involved_alert_ids, 'ALERT-COMBINER-1'))
                    logging.info(f"Findings count {len(FINDINGS_CACHE)}")

        # alert combiner 2 alert
        attack_simulation = df_forta_alerts[df_forta_alerts["alertId"] == "AK-ATTACK-SIMULATION-0"]
        addresses = set()
        for index, row in attack_simulation.iterrows():
            addresses = addresses.union(set(row['addresses']))

        # analyze each address' alerts
        for potential_attacker_address in addresses:
            logging.debug(potential_attacker_address)
            # if address is a contract or unlikely address, skip
            if(is_contract(w3, potential_attacker_address) or not is_address(w3, potential_attacker_address)):
                continue

            # map each alert to 4 stages
            stages = set()
            involved_addresses = set()
            if(len(df_forta_alerts) > 0):
                address_alerts = df_forta_alerts[df_forta_alerts["addresses"].apply(lambda x: potential_attacker_address in x if x is not None else False)]
                involved_alert_ids = address_alerts["alertId"].unique()
                for alert_id in involved_alert_ids:
                    if alert_id in ALERT_ID_STAGE_MAPPING.keys():
                        stage = ALERT_ID_STAGE_MAPPING[alert_id]
                        stages.add(stage)
                        # get addresses from address field to add to involved_addresses
                        address_alerts[address_alerts["alertId"] == alert_id]["addresses"].apply(lambda x: involved_addresses.update(set(x)))
                        logging.info(f"Found alert {alert_id} in stage {stage} for address {potential_attacker_address}")

                logging.info(f"Address {potential_attacker_address} stages: {stages}")

                # if funding stage is also observed, update the address alerted list and add a finding
                if 'Funding' in stages and Web3.toChecksumAddress(potential_attacker_address) not in ALERTED_ADDRESSES:
                    tx_count = w3.eth.get_transaction_count(Web3.toChecksumAddress(potential_attacker_address))
                    if tx_count > TX_COUNT_FILTER_THRESHOLD:
                        logging.info(f"Address {potential_attacker_address} transacton count: {tx_count}")
                        continue
                    update_alerted_addresses(w3, potential_attacker_address)
                    FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(potential_attacker_address, start_date, end_date, involved_addresses, involved_alert_ids, 'ALERT-COMBINER-2'))
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

        # uncomment for local testing of tx/block ranges (ok for npm run start); otherwise the process will exit
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
