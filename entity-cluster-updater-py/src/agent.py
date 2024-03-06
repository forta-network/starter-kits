import os
import time
import logging
import forta_agent
import pandas as pd
from web3 import Web3
from forta_agent import get_json_rpc_url

from src.storage import dynamo_table, get_secrets
from src.dynamo_utils import DynamoUtils
from src.constants import ENTITY_CLUSTER_BOT, ENTITY_CLUSTER_BOT_ALERT_ID

# If we are in production, we log to the console. Otherwise, we log to a file
if 'production' in os.environ.get('NODE_ENV', ''):
    logging.basicConfig(level=logging.INFO, 
                        format='%(levelname)s:%(asctime)s:%(name)s:%(lineno)d:%(message)s')
else:
    logging.basicConfig(filename=f"logs.log", level=logging.INFO, 
                        format='%(levelname)s:%(asctime)s:%(name)s:%(lineno)d:%(message)s')
logger = logging.getLogger(__name__)


TEST_TAG = "attack-detector-test_v2"
BETA_ALT_TAG = "attack-detector-beta_alt"
PROD_TAG = "attack-detector-prod"
tags = [TEST_TAG, BETA_ALT_TAG, PROD_TAG] 

# Initialize web3
web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global CHAIN_ID
    try:
        chain_id_temp = os.environ.get('FORTA_CHAIN_ID')
        if chain_id_temp is None:
            CHAIN_ID = web3.eth.chain_id
        else:
            CHAIN_ID = int(chain_id_temp)
        logging.info(f"Set chain id to {CHAIN_ID}")
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e
    logging.debug('initializing')
    global dynamo
    secrets = get_secrets()
    dynamo = dynamo_table(secrets)
    logging.info(f"Initialized dynamo DB successfully.")

    subscription_json = []
    subscription_json.append({"botId": ENTITY_CLUSTER_BOT, "alertId": ENTITY_CLUSTER_BOT_ALERT_ID, "chainId": CHAIN_ID})
    if CHAIN_ID in [10, 42161]:
        subscription_json.append({"botId": ENTITY_CLUSTER_BOT, "alertId": ENTITY_CLUSTER_BOT_ALERT_ID, "chainId": 1})

    return {"alertConfig": {"subscriptions": subscription_json}}


def update_clusters(du, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    # update entity clusters
    logger.info(f"alert {alert_event.alert_hash} is entity cluster alert")
    start = time.time()
    cluster = alert_event.alert.metadata["entityAddresses"].lower()

    for address in cluster.split(','):
        du.put_entity_cluster(dynamo, alert_event.alert.created_at, address, cluster)
        
        stored_alert_data_address = du.read_alert_data(dynamo, address)

        if not stored_alert_data_address.empty:
            du.delete_alert_data(dynamo, address)
            stored_alert_data_cluster = du.read_alert_data(dynamo, cluster)
            if not stored_alert_data_cluster.empty:
                alert_data_cluster = pd.concat([stored_alert_data_address, stored_alert_data_cluster], ignore_index=True, axis=0).drop_duplicates(subset=['stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'transaction_hash'], inplace=False)
            else:
                alert_data_cluster = stored_alert_data_address.drop_duplicates(subset=['stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'transaction_hash'], inplace=False)
            du.put_alert_data(dynamo, cluster, alert_data_cluster)
        
        if address in du.read_fp_mitigation_clusters(dynamo):
            du.put_fp_mitigation_cluster(dynamo, cluster)
        if address in du.read_end_user_attack_clusters(dynamo):
            du.put_end_user_attack_cluster(dynamo, cluster)
    end = time.time()
    logger.info(f"entity cluster alert {alert_event.alert_hash} processed in {end - start} seconds")
    return []


def provide_handle_alert(tags):
    logging.debug("provide_handle_alert called")
    chain_id = web3.eth.chain_id

    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        logging.debug("handle_alert inner called")

        findings = []
        for tag in tags:
            du = DynamoUtils(tag, chain_id)
            logger.info(f"update_clusters called for tag {tag}")

            findings.extend(update_clusters(du, alert_event))
        return findings

    return handle_alert


real_handle_alert = provide_handle_alert(tags)

def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    logging.debug("handle_alert called")
    return real_handle_alert(alert_event)