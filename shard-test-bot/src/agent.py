import logging
import sys
import os
import json
from datetime import datetime


import forta_agent
from forta_agent import get_json_rpc_url, EntityType, Finding, FindingType, FindingSeverity, Label, EntityType
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

def parse_datetime_with_high_precision(time_str):
    # Split the string at the decimal point of the seconds
    time_str_split = time_str.split(".")
    
    # Truncate or round the fractional part to 6 digits
    fractional_seconds = round(float("0." + time_str_split[1][:-1]), 6)
    
    # Parse the truncated string into a datetime object
    dt = datetime.strptime(time_str_split[0], "%Y-%m-%dT%H:%M:%S")
    
    # Add the truncated microseconds
    dt = dt.replace(microsecond=int(fractional_seconds * 1e6))
    
    return dt

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
    logging.info(alert_event.alert.created_at)
    dt = parse_datetime_with_high_precision(alert_event.alert.created_at)
    unix_timestamp = (dt - datetime(1970, 1, 1)).total_seconds()
    unix_timestamp_sec = int(unix_timestamp)
    shard = unix_timestamp_sec % 8

    logging.info(f"{BOT_VERSION} alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} {unix_timestamp} {shard} received")
    finding = Finding({
            'name': 'Shard test bot',
            'description': f'{shard},{unix_timestamp},{alert_event.alert_hash},{alert_event.bot_id},{alert_event.alert.alert_id},observed)',
            'alert_id': "SHARD-TEST-1",
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': []
        })
    return [finding]




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

