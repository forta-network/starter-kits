import logging
import sys
import os
import json
from datetime import datetime, timedelta


import forta_agent
from forta_agent import get_json_rpc_url, EntityType, Finding, FindingType, FindingSeverity, Label, EntityType
from web3 import Web3

from src.storage import s3_client, dynamo_table, get_secrets, bucket_name
from src.constants import (BASE_BOTS)

s3 = None
dynamo = None
item_id_prefix = ""

CHAIN_ID = -1
BOT_VERSION = "0.0.0"

INITIALIZED = False
INITIALIZATION_TIME = datetime.now()

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



def reinitialize():
    global CHAIN_ID
    global BOT_VERSION
    global s3
    global dynamo

    try:
        # initialize dynamo DB
        if dynamo is None:
            secrets = get_secrets()
            s3 = s3_client(secrets)
            dynamo = dynamo_table(secrets)
            logging.info(f"{BOT_VERSION}: Initialized dynamo DB successfully.")
    except Exception as e:
        logging.error(f"{BOT_VERSION}: Error initializing dynamo DB: {e}")
        raise e
        
    try:
        if CHAIN_ID == -1:
            chain_id_temp = os.environ.get('FORTA_CHAIN_ID')
            if chain_id_temp is None:
                CHAIN_ID = web3.eth.chain_id
            else:
                CHAIN_ID = int(chain_id_temp)
        logging.info(f"{BOT_VERSION}: Set chain id to {CHAIN_ID}")
    except Exception as e:
        logging.error(f"{BOT_VERSION}: Error getting chain id: {e}")
        raise e

def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global CHAIN_ID
    global INITIALIZED
    try:
        reinitialize()
        global BOT_VERSION
        BOT_VERSION = get_bot_version()
        
        # subscribe to the base bots, FP mitigation and entity clustering bot
        global BASE_BOTS
        subscription_json = []
        for botId, alertId, alert_logic, target_alert_id in BASE_BOTS:
            subscription_json.append({"botId": botId, "alertId": alertId, "chainId": CHAIN_ID})

        alert_config = {"alertConfig": {"subscriptions": subscription_json}}
        logging.info(f"Initializing shard test bot. Subscribed to bots successfully: {alert_config}")
        logging.info(f"Initialized shard test bot.")
        INITIALIZED = True

    except Exception as e:
        logging.error(f"{BOT_VERSION}: Error initializing shard test bot: {e}")
        sys.exit(1)

    return alert_config


# clear cache flag for perf testing
def detect_scam(w3, alert_event: forta_agent.alert_event.AlertEvent, clear_state_flag = False) -> list:
    global BOT_VERSION
    logging.info(alert_event.alert.created_at)
    dt = parse_datetime_with_high_precision(alert_event.alert.created_at)
    unix_timestamp = (dt - datetime(1970, 1, 1)).total_seconds()
    unix_timestamp_sec = int(unix_timestamp)
    shard = unix_timestamp_sec % 8

    
    logging.info(f"{BOT_VERSION} alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} {unix_timestamp} {shard} {len(alert_event.alert.labels)} received")
    labels = []
    # labels.append(Label({
    #                 'entityType': EntityType.Transaction,
    #                 'label': "test-label",
    #                 'entity': alert_event.transaction_hash,
    #                 'confidence': 0.8,
    #                 'metadata': {
    #                     'alert_ids': alert_event.alert.alert_id
    #                 }   
    #                 }))
    finding = Finding({
            'name': 'Shard test bot',
            'description': f'{shard},{unix_timestamp},{alert_event.alert_hash},{alert_event.bot_id},{alert_event.alert.alert_id},observed)',
            'alert_id': "SHARD-TEST-2",
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': labels
        })
    return [finding]




def provide_handle_alert(w3):
    logging.debug("provide_handle_alert called")

    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        logging.debug("handle_alert inner called")

        global INITIALIZED
        global INITIALIZATION_TIME
        if not INITIALIZED:
            time_elapsed = datetime.now() - INITIALIZATION_TIME
            if (time_elapsed > timedelta(minutes=5)):
                logging.error(f"{BOT_VERSION}: Not initialized handle alert {INITIALIZED}. Time elapsed: {time_elapsed}. Exiting.")
                sys.exit(1)
            else:
                logging.warning(f"{BOT_VERSION}: Not initialized handle alert {INITIALIZED}. Time elapsed: {time_elapsed}. Returning.")
                return []
            
        findings = detect_scam(w3, alert_event)
        return findings

    return handle_alert


real_handle_alert = provide_handle_alert(web3)


def handle_alert(alert_event: forta_agent.alert_event.AlertEvent):
    logging.debug("handle_alert called")
    return real_handle_alert(alert_event)

