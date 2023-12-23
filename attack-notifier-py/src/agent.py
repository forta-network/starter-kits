from forta_agent import Finding, FindingType, FindingSeverity,get_json_rpc_url
import forta_agent
import os
import requests
import json
from datetime import datetime, timezone
import time
from ratelimiter import RateLimiter
import sys
import queue
from web3 import Web3
import logging

from src.storage import get_secrets
from datetime import datetime, timezone


CHAIN_ID = -1
WAIT_TIME = 60 # minutes
SECRETS_JSON = None
ATTACKER_ADDRESSES = {} # contract and creation timestamp

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


root = logging.getLogger()
root.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

def initialize():
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
    

    subscription_json = []
    subscription_json.append({"botId": "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1", "chainId": CHAIN_ID})
    return {"alertConfig": {"subscriptions": subscription_json}}

def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    findings = []
    global ATTACKER_ADDRESSES

    chain_id = int(alert_event.chain_id)
    if chain_id == CHAIN_ID:
        logging.info(f"alert {alert_event.alert_hash} received for proper chain {chain_id}")

        if "FALSE" not in alert_event.alert_id:
            addresses = alert_event.alert.description.split(" ")[0]
            ATTACKER_ADDRESSES[addresses] = alert_event
            logging.info(f"Added {addresses} to queue")
    return findings

def handle_blocks(block_event: forta_agent.block_event.BlockEvent) -> list:
    findings = []
    global ATTACKER_ADDRESSES

    for (addresses, retrieved_alert_event) in ATTACKER_ADDRESSES.copy().items():
        logging.info(f"{datetime.now(timezone.utc)} - Assessing {addresses} created at {retrieved_alert_event.alert.created_at}")
        # created_at string in format 2023-11-11T01:08:35.08635455Z
        created_at_date = datetime.strptime(retrieved_alert_event.alert.created_at[0:19], "%Y-%m-%dT%H:%M:%S")
        created_at_date_utc = created_at_date.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - created_at_date_utc).total_seconds() >= WAIT_TIME * 60: # 60 min
            logging.info(f"Removing {addresses} from queue")
            del ATTACKER_ADDRESSES[addresses]
            labels = get_etherscan_labels(addresses, retrieved_alert_event.alert.chain_id)
            for label in labels:
                if "exploiter" in label.lower() or "hack" in label.lower():
                    findings.append(Finding({
                        'name':"Attributed Exploit Identified by Attack Detector",
                        'description':f"{addresses} have been associated with {label}",
                        'alert_id':"ATTACK-NOTIFIER-1",
                        'severity':FindingSeverity.Critical,
                        'type':FindingType.Exploit
                    }))

    return findings



def get_api_key(chain_id):
    global SECRETS_JSON
    if SECRETS_JSON is None:
        SECRETS_JSON = get_secrets()

    if chain_id == 1:
        return SECRETS_JSON['apiKeys']['ETHERSCAN_TOKEN']
    elif chain_id == 137:
        return SECRETS_JSON['apiKeys']['POLYGONSCAN_TOKEN']
    elif chain_id == 56:
        return SECRETS_JSON['apiKeys']['BSCSCAN_TOKEN']
    elif chain_id == 42161:
        return SECRETS_JSON['apiKeys']['ARBISCAN_TOKEN']
    elif chain_id == 10:
        return SECRETS_JSON['apiKeys']['OPTIMISTICSCAN_TOKEN']
    elif chain_id == 250:
        return SECRETS_JSON['apiKeys']['FTMSCAN_TOKEN']
    elif chain_id == 43114:
        return SECRETS_JSON['apiKeys']['SNOWTRACE_TOKEN']
    
    raise Exception("Chain ID not supported")

@RateLimiter(max_calls=1, period=1)
def get_etherscan_labels(addresses, chain_id) -> set:
    labels_url = f"https://api-metadata.etherscan.io/v1/api.ashx?module=nametag&action=getaddresstag&address={addresses}&tag=trusted&apikey={get_api_key(chain_id)}"
    labels = set()
    success = False
    count = 0
    while not success:
        data = requests.get(labels_url)
        if data.status_code == 200:
            json_data = json.loads(data.content)
            success = True 
            if "result" in json_data:
                result_data = json_data.get("result")
                if isinstance(result_data, list) and result_data:
                    labels.update(result_data[0].get("labels", []))
                    labels.add(result_data[0].get("nametag", ""))
                elif isinstance(result_data, str):
                    logging.warning(f"Etherscan Error Response: {data.content}.")
                else:
                    logging.warning(f"Etherscan response does not contain valid data {data.content}.")
            else:
                logging.warning(f"Etherscan response does not contain 'result' field: {data.content}.")
        else:
            logging.warning(f"Error getting labels on etherscan: {data.status_code} {data.content}.")
            count += 1
            if count > 10:
                break
            time.sleep(1)
    return labels
