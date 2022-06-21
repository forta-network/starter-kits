import logging
import sys
import threading
from datetime import datetime, timedelta

import forta_agent
import pandas as pd
from forta_agent import get_json_rpc_url
from web3 import Web3

from constants import (BOT_ID, ALERT_NAME, CONTRACT_ADDRESS, BUCKET_WINDOW_IN_MINUTES, TRAINING_WINDOW_IN_BUCKET_SIZE, INTERVAL_WIDTH)
from findings import TimeSeriesAnalyzerFinding
from forta_explorer import FortaExplorer

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
forta_explorer = FortaExplorer()

FINDINGS_CACHE = []
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
    global FINDINGS_CACHE
    FINDINGS_CACHE = []

    global MUTEX
    MUTEX = False


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
        start_date = end_date - timedelta(minutes=BUCKET_WINDOW_IN_MINUTES * TRAINING_WINDOW_IN_BUCKET_SIZE)
        logging.info(f"Analyzing alerts from {start_date} to {end_date}")

        # get all alerts for date range
        bot_alerts = forta_explorer.alerts_by_bot(BOT_ID, ALERT_NAME, CONTRACT_ADDRESS, start_date, end_date)
        logging.info(f"Fetched {len(bot_alerts)} for bot_id {BOT_ID}, alert_id {ALERT_NAME}, contract_address {CONTRACT_ADDRESS}")

        # build time series model without last bucket
        timeseries = bot_alerts.resample('5min', on='createdAt').count()["hash"].reset_index()
        print(timeseries)

        # fix missing values

        # assess whether last bucket is a breakout and alert if so
        #            FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(potential_attacker_address, start_date, end_date, involved_addresses, involved_alert_ids))
        #            logging.info(f"Findings count {len(FINDINGS_CACHE)}")

        MUTEX = False


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
        while (thread.is_alive()):
            pass
        findings = FINDINGS_CACHE
        FINDINGS_CACHE = []
        return findings

    return handle_block


real_handle_block = provide_handle_block(web3, forta_explorer)


def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)
