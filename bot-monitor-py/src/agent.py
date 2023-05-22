import logging
import datetime
import sys
import os
import json
import traceback
from datetime import datetime, timedelta, timezone

from src.constants import MONITORED_BOTS
from src.models import AlertRateModel
from src.L2Cache import L2Cache

import forta_agent
from forta_agent import get_json_rpc_url, Finding, FindingType, FindingSeverity
from web3 import Web3

CHAIN_ID = -1
START_TIME = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
MODELS = {}
FINDINGS_CACHE = []
BOT_VERSION = None

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


def get_bot_version() -> str:
    global BOT_VERSION
    if BOT_VERSION is None:
        logging.debug("getting bot version from package.json")
        package = json.load(open("package.json"))
        logging.debug("loaded package.json")
        BOT_VERSION = package["version"]
    return BOT_VERSION
    

def initialize():
    global CHAIN_ID
    try:
        CHAIN_ID = os.environ.get('FORTA_CHAIN_ID')
        if CHAIN_ID is None:
            CHAIN_ID = web3.eth.chain_id
        else:
            CHAIN_ID = int(CHAIN_ID)
        logging.info(f"Set chain id to {CHAIN_ID}")
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e
    
    global MODELS
    models = L2Cache.load(CHAIN_ID, "MODELS")
    MODELS = dict() if models is None else dict(models)

    global FINDINGS_CACHE
    findings_cache = L2Cache.load(CHAIN_ID, "FINDINGS_CACHE")
    FINDINGS_CACHE = list() if findings_cache is None else list(findings_cache)


    global MONITORED_BOTS
    subscription_json = []
    for bot_id, alert_id in MONITORED_BOTS:
        subscription_json.append({"botId": bot_id, "alertId": alert_id, "chainId": CHAIN_ID})
        if bot_id not in MODELS.keys():
            MODELS[bot_id] = {}
        MODELS[bot_id][alert_id] = AlertRateModel()
        MODELS[bot_id][alert_id].update(START_TIME - timedelta(hours=1))

    alert_config = {"alertConfig": {"subscriptions": subscription_json}}
    logging.info(f"Initializing monitoring bot. Subscribed to bots successfully: {alert_config}")
    logging.info("Initialized monitoring bot.")
    return alert_config


def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global START_TIME
    global CHAIN_ID
    global MODELS
    global FINDINGS_CACHE

    findings = []
    try:
        logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got alert at {alert_event.alert.created_at}")

        current_time = datetime.strptime(alert_event.alert.created_at[0:13], "%Y-%m-%dT%H")
        current_time_utc = current_time.replace(tzinfo=timezone.utc)
        model = MODELS[alert_event.bot_id][alert_event.alert_id]
        model.update(current_time_utc)
        time_series_length = len(model.data)
        logging.info(f"{get_bot_version()}: bot {alert_event.bot_id} alertId {alert_event.alert.alert_id} - time series length: {time_series_length}")
        last_hour = current_time_utc - timedelta(hours=1)
        logging.info(f"{get_bot_version()}: bot {alert_event.bot_id} alertId {alert_event.alert.alert_id} - time series: {model.get_time_series_data(current_time_utc, START_TIME)}")

        # Check for cold start
        if (current_time_utc - START_TIME).days < 1:
            return findings

        # Check if the alert rate is outside the normal range
        findings_cache_key = f"{alert_event.bot_id}, {alert_event.alert_id}, {CHAIN_ID}, {last_hour}"
        lower_bound, upper_bound, actual_value = model.get_normal_range(last_hour, START_TIME)  # this only builds the model once per hour

        logging.info(f"{get_bot_version()}: {findings_cache_key} - lower bound: {lower_bound}, upper bound: {upper_bound}, actual value: {actual_value}")

        if (actual_value < lower_bound or actual_value > upper_bound) and findings_cache_key not in FINDINGS_CACHE:
            findings.append(Finding({
                    'name': 'Monitor bot identified abnormal alert range.',
                    'description': f'{alert_event.bot_id}, {alert_event.alert_id}, {CHAIN_ID} alert rate outside of normal range at {last_hour}.',
                    'alert_id': "ALERT-RATE-ANOMALY",
                    'type': FindingType.Info,
                    'severity': FindingSeverity.Info,
                    'metadata': {
                        'lower_bound': lower_bound,
                        'upper_bound': upper_bound,
                        'actual_value': actual_value,
                        'time_series_data': model.get_time_series_data(last_hour, START_TIME)
                    }
                }))
            FINDINGS_CACHE.append(findings_cache_key)
    except BaseException as e:
        logging.warning(f"{get_bot_version()}: alert {alert_event.alert_hash} - Exception in process_alert {alert_event.alert_hash}: {e} - {traceback.format_exc()}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"{get_bot_version()}: alert {alert_event.alert_hash} - Raising exception to expose error to scannode")
            raise e
        
    return findings


def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
    global FINDINGS_CACHE
    global MODELS

    logging.debug("handle_block with w3 called")
    findings = []
    if datetime.now().minute == 0:  # every hour
        L2Cache.write(FINDINGS_CACHE, CHAIN_ID, "FINDINGS_CACHE")
        L2Cache.write(MODELS, CHAIN_ID, "MODELS")
    return findings
