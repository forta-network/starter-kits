import logging
import sys
import threading
from datetime import datetime, timedelta

import forta_agent
import pandas as pd
from forta_agent import FindingSeverity, FindingType, get_json_rpc_url
from prophet import Prophet
from web3 import Web3

from src.constants import (ALERT_NAME, BOT_ID, BUCKET_WINDOW_IN_MINUTES,
                           CONTRACT_ADDRESS, INTERVAL_WIDTH,
                           TIMESTAMP_QUEUE_SIZE,
                           TRAINING_WINDOW_IN_BUCKET_SIZE)
from src.findings import TimeSeriesAnalyzerFinding
from src.forta_explorer import FortaExplorer

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
forta_explorer = FortaExplorer()

FINDINGS_CACHE = []
ALERTED_TIMESTAMP = []
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
    global ALERTED_TIMESTAMP
    ALERTED_TIMESTAMP = []

    global FINDINGS_CACHE
    FINDINGS_CACHE = []

    global MUTEX
    MUTEX = False


def get_finding_type(finding_type: str) -> FindingType:
    if finding_type == "EXPLOIT":
        return FindingType.Exploit
    if finding_type == "DEGRADED":
        return FindingType.Degraded
    if finding_type == "INFO":
        return FindingType.Info
    if finding_type == "SUSPICIOUS":
        return FindingType.Suspicious

    return FindingType.Unknown


def get_finding_severity(finding_severity: str) -> FindingSeverity:
    if finding_severity == "INFO":
        return FindingSeverity.Info
    if finding_severity == "CRITICAL":
        return FindingSeverity.Critical
    if finding_severity == "HIGH":
        return FindingSeverity.High
    if finding_severity == "MEDIUM":
        return FindingSeverity.Medium
    if finding_severity == "LOW":
        return FindingSeverity.Low

    return FindingSeverity.Unknown


def update_alerted_timestamp(timestamp: datetime):
    """
    this function maintains a time stamps; holds up to TIMESTAMP_QUEUE_SIZE in memory
    :return: None
    """
    global ALERTED_TIMESTAMP

    ALERTED_TIMESTAMP.append(timestamp)
    if len(ALERTED_TIMESTAMP) > TIMESTAMP_QUEUE_SIZE:
        ALERTED_TIMESTAMP.pop(0)


def detect_attack(w3, forta_explorer, block_event: forta_agent.block_event.BlockEvent):
    """
    this function returns finding for any alert frequency for the most recent BUCKET that breaks out the predicted range by the Prophet time series model.
    :return: findings: list
    """
    global ALERTED_TIMESTAMP
    global FINDINGS_CACHE
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

        if len(df_bot_alerts) == 0:
            logging.info("No alerts found for bot_id {BOT_ID}, alert_id {ALERT_NAME}, contract_address {CONTRACT_ADDRESS}")
            MUTEX = False
            return

        # build time series model without last bucket
        df_timeseries = df_bot_alerts.resample(str(BUCKET_WINDOW_IN_MINUTES) + 'min', on='createdAt').count()["hash"].reset_index()
        df_timeseries['createdAt'] = df_timeseries['createdAt'].dt.tz_localize(None)

        if len(df_timeseries) < 3:
            logging.info("Not enough data to train model")
            MUTEX = False
            return

        df_timeseries = df_timeseries[df_timeseries["createdAt"] < df_timeseries["createdAt"].max()]  # this row could be incomplete, so we discard
        df_current_value = df_timeseries[df_timeseries["createdAt"] == df_timeseries["createdAt"].max()]
        df_timeseries = df_timeseries[df_timeseries["createdAt"] < df_timeseries["createdAt"].max()]  # this row is what we want to assess against the model, so we discard

        df_timeseries.rename(columns={'createdAt': 'ds', 'hash': 'y'}, inplace=True)
        df_timeseries['ds'] = df_timeseries['ds'].dt.tz_localize(None)

        # fill in missing values with median
        median = df_timeseries['y'].median()
        logging.info(f"Median is {median}.")
        current_date = start_date - timedelta(minutes=start_date.minute % BUCKET_WINDOW_IN_MINUTES,
                                              seconds=start_date.second,
                                              microseconds=start_date.microsecond)
        current_date += timedelta(minutes=BUCKET_WINDOW_IN_MINUTES)

        # first ensure we have values that span start to end date
        count = 0
        while(current_date < end_date - timedelta(minutes=BUCKET_WINDOW_IN_MINUTES)):
            if pd.Timestamp(current_date) not in df_timeseries['ds'].values:
                count += 1
                df_timeseries = pd.concat([df_timeseries, pd.DataFrame({'ds': current_date, 'y': median}, index=[df_timeseries.index.max() + 1])])
            current_date = current_date + timedelta(minutes=BUCKET_WINDOW_IN_MINUTES)
        logging.info(f"Filled in {count} values.")

        # for any values we do have that are 0, replace with median
        logging.info(f"Replaced {len(df_timeseries[df_timeseries['y'] == 0])} values with median.")
        df_timeseries.replace(0, median, inplace=True)

        m = Prophet(interval_width=INTERVAL_WIDTH)
        m.fit(df_timeseries)
        future = m.make_future_dataframe(periods=1, freq=str(BUCKET_WINDOW_IN_MINUTES) + 'min')
        model = m.predict(future)
        logging.info("Built model.")

        current_value = df_current_value["hash"].iloc[0]
        forecast = model[model["ds"] == df_current_value["createdAt"].iloc[0]]
        yhat = forecast["yhat"].iloc[0]
        yhat_lower = forecast["yhat_lower"].iloc[0]
        yhat_upper = forecast["yhat_upper"].iloc[0]
        logging.info(f"Forecast: yhat={yhat}, yhat_lower={yhat_lower}, yhat_upper={yhat_upper}; current_value={current_value}")

        finding_type = get_finding_type(df_bot_alerts.iloc[0]["findingType"])
        finding_severity = get_finding_severity(df_bot_alerts.iloc[0]["severity"])
        if df_current_value["createdAt"].iloc[0] not in ALERTED_TIMESTAMP:
            update_alerted_timestamp(df_current_value["createdAt"].iloc[0])
            if current_value > yhat_upper:
                logging.info(f"Alert detected for {CONTRACT_ADDRESS}")
                FINDINGS_CACHE.append(TimeSeriesAnalyzerFinding.breakout("Upside", yhat, yhat_upper, current_value, CONTRACT_ADDRESS, BOT_ID, ALERT_NAME, finding_type, finding_severity))
            if current_value < yhat_lower and current_value != 0:  # don't alert if current value is 0 because there are reliability issues leading to bot not running and resulting in 0 alerts. Once the reliability increases, this condition can be removed.
                logging.info(f"Alert detected for {CONTRACT_ADDRESS}")
                FINDINGS_CACHE.append(TimeSeriesAnalyzerFinding.breakout("Downside", yhat, yhat_lower, current_value, CONTRACT_ADDRESS, BOT_ID, ALERT_NAME, finding_type, finding_severity))

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
        #while (thread.is_alive()):
        #    pass
        findings = FINDINGS_CACHE
        FINDINGS_CACHE = []
        return findings

    return handle_block


real_handle_block = provide_handle_block(web3, forta_explorer)


def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)
