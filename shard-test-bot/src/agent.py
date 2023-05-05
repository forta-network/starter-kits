import logging
import sys
import os
import json
from datetime import datetime


import forta_agent
from forta_agent import get_json_rpc_url, EntityType
from web3 import Web3

from src.constants import (BASE_BOTS)

CHAIN_ID = -1
BOT_VERSION = "0.0.0"

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)



def get_bot_version() -> str:
    logging.debug("getting bot version from package.json")
    package = json.load(open("package.json"))
    logging.debug("loaded package.json")
    return package["version"]


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global CHAIN_ID
    try:
        if CHAIN_ID == -1:
            chain_id_temp = os.environ.get('FORTA_CHAIN_ID')
            if chain_id_temp is None:
                CHAIN_ID = web3.eth.chain_id
            else:
                CHAIN_ID = int(chain_id_temp)
        logging.info(f"Set chain id to {CHAIN_ID}")
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e
    
    global BOT_VERSION
    BOT_VERSION = get_bot_version()
    
    # subscribe to the base bots, FP mitigation and entity clustering bot
    global BASE_BOTS
    subscription_json = []
    for botId, alertId, alert_logic, target_alert_id in BASE_BOTS:
        subscription_json.append({"botId": botId, "alertId": alertId, "chainId": CHAIN_ID})

    alert_config = {"alertConfig": {"subscriptions": subscription_json}}
    logging.info(f"Initializing scam detector bot. Subscribed to bots successfully: {alert_config}")
    logging.info(f"Initialized scam detector bot.")
    return alert_config


# clear cache flag for perf testing
def detect_scam(w3, alert_event: forta_agent.alert_event.AlertEvent, clear_state_flag = False) -> list:
    global BOT_VERSION
    logging.info(f"{BOT_VERSION} alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} received")
    return []




def provide_handle_alert(w3):
    logging.debug("provide_handle_alert called")

    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        logging.debug("handle_alert inner called")
        findings = detect_scam(w3, alert_event)
        return findings

    return handle_alert


real_handle_alert = provide_handle_alert(web3)


def handle_alert(alert_event: forta_agent.alert_event.AlertEvent):
    logging.debug("handle_alert called")
    return real_handle_alert(alert_event)

