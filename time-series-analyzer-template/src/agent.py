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
from prophet import Prophet
from forta_agent import FindingSeverity, FindingType

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
        df_bot_alerts = forta_explorer.alerts_by_bot(BOT_ID, ALERT_NAME, CONTRACT_ADDRESS, start_date, end_date)
        logging.info(f"Fetched {len(df_bot_alerts)} for bot_id {BOT_ID}, alert_id {ALERT_NAME}, contract_address {CONTRACT_ADDRESS}")

        # build time series model without last bucket
        df_timeseries = df_bot_alerts.resample(str(BUCKET_WINDOW_IN_MINUTES)+'min', on='createdAt').count()["hash"].reset_index()
        df_timeseries['createdAt'] = df_timeseries['createdAt'].dt.tz_localize(None)

        df_timeseries = df_timeseries[df_timeseries["createdAt"] < df_timeseries["createdAt"].max()] # this row could be incomplete, so we discard
        df_current_value = df_timeseries[df_timeseries["createdAt"] == df_timeseries["createdAt"].max()]  
        df_timeseries = df_timeseries[df_timeseries["createdAt"] < df_timeseries["createdAt"].max()] # this row is what we want to assess against the model, so we discard
        
        # TODO - fix missing values

        df_timeseries.rename(columns={'createdAt': 'ds', 'hash': 'y'}, inplace=True)
        df_timeseries['ds'] = df_timeseries['ds'].dt.tz_localize(None)

        m = Prophet(interval_width=INTERVAL_WIDTH)
        m.fit(df_timeseries)
        future = m.make_future_dataframe(periods=1, freq=str(BUCKET_WINDOW_IN_MINUTES)+'min')
        model = m.predict(future)
        #forecast[['ds', 'yhat', 'yhat_lower', 'yhat_upper']].tail()

        current_value = df_current_value["hash"].iloc[0]
        forecast = model[model["ds"] == df_current_value["createdAt"].iloc[0]]
        yhat = forecast["yhat"].iloc[0]
        yhat_lower = forecast["yhat_lower"].iloc[0]
        yhat_upper = forecast["yhat_upper"].iloc[0]


        if current_value > yhat_upper:
            logging.info(f"Alert detected for {CONTRACT_ADDRESS}")
            FINDINGS_CACHE.append(TimeSeriesAnalyzerFinding.breakout("Upside", yhat, yhat_upper, current_value, CONTRACT_ADDRESS, BOT_ID, ALERT_NAME, FindingType.Info, FindingSeverity.Low))  # TODO - pass through finding type and severity
        if current_value < yhat_lower:
            logging.info(f"Alert detected for {CONTRACT_ADDRESS}")
            FINDINGS_CACHE.append(TimeSeriesAnalyzerFinding.breakout("Downside", yhat, yhat_lower, current_value, CONTRACT_ADDRESS, BOT_ID, ALERT_NAME, FindingType.Info, FindingSeverity.Low))

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
