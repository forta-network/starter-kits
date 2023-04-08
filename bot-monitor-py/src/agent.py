import logging
import datetime
import sys
import os
from datetime import datetime, timedelta

from src.constants import MONITORED_BOTS
from src.models import AlertRateModel

import forta_agent
from forta_agent import get_json_rpc_url, Finding, FindingType, FindingSeverity
from web3 import Web3

CHAIN_ID = -1
START_TIME = datetime.now()
MODELS = {}
FINDINGS_CACHE = []

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

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
    global MONITORED_BOTS
    subscription_json = []
    for bot_id, alert_id in MONITORED_BOTS:
        subscription_json.append({"botId": bot_id, "alertId": alert_id, "chainId": CHAIN_ID})
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

    logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got alert at {alert_event.alert.created_at}")

    findings = []
    current_time = datetime.strptime(alert_event.alert.created_at[0:13], "%Y-%m-%dT%H")
    model = MODELS[alert_event.bot_id][alert_event.alert_id]
    model.update(current_time)

    # Check for cold start
    if (current_time - START_TIME).days < 1:
        return findings

    last_hour = current_time - timedelta(hours=1)
    
    # Check if the alert rate is outside the normal range
    findings_cache_key = f"{alert_event.bot_id}, {alert_event.alert_id}, {CHAIN_ID}, {last_hour}"
    lower_bound, upper_bound, actual_value = model.get_normal_range(last_hour, START_TIME)
    if (actual_value < lower_bound or actual_value>upper_bound) and findings_cache_key not in FINDINGS_CACHE:
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
    
    return findings
