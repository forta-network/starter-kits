import logging
import datetime
import sys
import os
from datetime import datetime, timedelta

from constants import MONITORED_BOTS
from models import AlertRateModel

import forta_agent
from forta_agent import get_json_rpc_url, Finding, FindingType, FindingSeverity
from web3 import Web3

CHAIN_ID = -1
START_TIME = datetime.datetime.now()
MODELS = {}

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

def initialize(self):
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
    
    global MONITORED_BOTS
    subscription_json = []
    for bot, alertId in MONITORED_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId, "chainId": CHAIN_ID})

    alert_config = {"alertConfig": {"subscriptions": subscription_json}}
    logging.info(f"Initializing monitoring bot. Subscribed to bots successfully: {alert_config}")
    logging.info("Initialized monitoring bot.")
    return alert_config


def handle_alert(self, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global START_TIME
    global CHAIN_ID
    global MODELS
    
    findings = []
    current_time = datetime.datetime.now()
    
    # Check for cold start
    if (current_time - START_TIME).days < 1:
        return findings
    
    bot_id = alert_event.bot_id
    if bot_id not in self.models:
        MODELS[bot_id] = {}
    
    alert_id = alert_event.alert_id
    if alert_id not in MODELS[bot_id]:
        MODELS[bot_id][alert_id] = AlertRateModel()
    
    model = MODELS[bot_id][alert_id]
    
    # update the model
    model.update(alert_event.alert.created_at)

    current_hour = datetime.now().replace(minute=0, second=0, microsecond=0) 
    last_hour = current_hour - timedelta(hours=1)
    
    # Check if the alert rate is outside the normal range
    if model.is_outside_normal_range(last_hour):
        findings.append(Finding({
                'name': 'Monitor bot identified abnormal alert range.',
                'description': f'{bot_id} {alert_id} {CHAIN_ID} alert rate outside of normal range.',
                'alert_id': "ALERT-RATE-ANOMALY",
                'type': FindingType.Info,
                'severity': FindingSeverity.Info
            }))
    
    return findings
