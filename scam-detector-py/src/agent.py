import logging
import sys
import requests
import os
import json
from datetime import datetime
import time

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3

from constants import (ENTITY_CLUSTER_BOTS, FP_MITIGATION_BOTS, BASE_BOTS, ALERT_LOOKBACK_WINDOW_IN_DAYS,
                         ENTITY_CLUSTERS_MAX_QUEUE_SIZE, FP_CLUSTERS_QUEUE_MAX_SIZE)
from storage import s3_client, dynamo_table, get_secrets, bucket_name

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

CHAIN_ID = 1

ENTITY_CLUSTERS = dict()  # address -> cluster
FP_MITIGATION_CLUSTERS = []  # cluster

s3 = None
dynamo = None

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

label_api = "https://api.forta.network/labels/state?sourceIds=etherscan,0x6f022d4a65f397dffd059e269e1c2b5004d822f905674dbf518d968f744c2ede&entities="

def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global CHAIN_ID
    try:
        CHAIN_ID = web3.eth.chain_id
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e
    
    # initialize dynamo DB
    global s3, dynamo
    secrets = get_secrets()
    s3 = s3_client(secrets)
    dynamo = dynamo_table(secrets)
    logging.info("Initializing scam detector bot. Initialized dynamo DB successfully.")

    # subscribe to the base bots, FP mitigation and entity clustering bot
    subscription_json = []
    for bot, alertId, stage in BASE_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId, "chainId": CHAIN_ID})

    for bot, alertId in FP_MITIGATION_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId, "chainId": CHAIN_ID})

    for bot, alertId in ENTITY_CLUSTER_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId, "chainId": CHAIN_ID})

    logging.info("Initializing scam detector bot. Subscribed to bots successfully.")
    logging.info("Initialized scam detector bot.")
    return subscription_json


def in_list(alert_event: forta_agent.alert_event.AlertEvent, bots: tuple) -> bool:
    """
    this function returns True if the alert is from a bot in the bots tuple
    :return: bool
    """
    for tup in bots:
        if alert_event.alert.source.bot.id == tup[0] and alert_event.alert.alert_id == tup[1]:
            return True

    return False


def get_etherscan_label(address: str) -> str:
    if address is None:
        return None
        
    try:
        res = requests.get(label_api + address.lower())
        if res.status_code == 200:
            labels = res.json()
            if len(labels) > 0:
                return labels['events'][0]['label']['label']
    except Exception as e:
        logging.warning(f"Exception in get_etherscan_label {e}")
        return None
    

def update_list(items: list, max_size: int, item: str):

    items.append(item.lower())

    while len(items) > max_size:
        items.pop(0)  # remove oldest item


def get_total_shards() -> int:
    package = json.load(open("package.json"))
    total_shards = package["chainSettings"][str(CHAIN_ID)]["shards"]
    return total_shards
    

def get_shard(block_number: int) -> int:
    total_shards = get_total_shards()
    return block_number % total_shards


# put in item alerts per cluster by shard id
# note, given sort key is part of the key, alerts with different hashes will result in different entries
# whereas alerts with the same hash will be overwritten
def put_alert(alert_event: forta_agent.alert_event.AlertEvent, cluster: str):
    shard = get_shard(alert_event.block_number)
    itemId = f"{CHAIN_ID}|{shard}|alert|{cluster}"

    expiry_offset = ALERT_LOOKBACK_WINDOW_IN_DAYS * 24 * 60 * 60
    alert_created_at_str = alert_event.alert.created_at
    alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()

    response = dynamo.put_item(Item={
        "itemId": itemId,
        "sortKey": f"{alert_event.alert.source.bot.id}|{alert_event.alert.alert_id}|{alert_event.alert_hash}",
        "botId": alert_event.alert.source.bot.id,
        "alertId": alert_event.alert.alert_id,
        "alertHash": alert_event.alert_hash,
        "cluster": cluster,
        "expiresAt": int(alert_created_at + expiry_offset)
    })

    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logging.error(f"Error putting alert in dynamoDB: {response}")
        return
    else:
        logging.info(f"Successfully put alert in dynamoDB: {response}")
        return


def read_alerts(cluster: str) -> list:
    alert_items = []
    for shard in range(get_total_shards()):
        itemId = f"{CHAIN_ID}|{shard}|alert|{cluster}"
        response = dynamo.query(KeyConditionExpression='itemId = :id',
                                ExpressionAttributeValues={
                                    ':id': itemId
                                }
                                )

        # Print retrieved item
        items = response.get('Items', [])

        for item in items:
            alert_items.append((item["botId"], item["alertId"], item["alertHash"]))
    return alert_items


def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    
    global ENTITY_CLUSTERS
    global CHAIN_ID
    
    findings = []
    try:
        start = time.time()

        chain_id = int(alert_event.alert.source.block.chain_id) if alert_event.alert.source.block.chain_id is not None else int(alert_event.chain_id)
        if chain_id == CHAIN_ID:
            # got alert from the right chain

            # update entity clusters
            if in_list(alert_event, ENTITY_CLUSTER_BOTS):
                    logging.info(f"alert {alert_event.alert_hash} is entity cluster alert")
                    cluster = alert_event.alert.metadata["entityAddresses"].lower()

                    for address in cluster.split(','):
                        ENTITY_CLUSTERS[address] = cluster
                        logging.info(f"alert {alert_event.alert_hash} - adding cluster mapping: {address} -> {cluster}")
                        while len(ENTITY_CLUSTERS) > ENTITY_CLUSTERS_MAX_QUEUE_SIZE:
                            ENTITY_CLUSTERS.pop(next(iter(ENTITY_CLUSTERS)))
                        logging.info(f"alert {alert_event.alert_hash} entity clusters size now: {len(ENTITY_CLUSTERS)}")

            # update FP mitigation clusters
            if in_list(alert_event, FP_MITIGATION_BOTS):
                logging.info(f"alert {alert_event.alert_hash} is a FP mitigation alert")
                address = alert_event.alert.description[0:42]
                cluster = address
                if address in ENTITY_CLUSTERS.keys():
                    cluster = ENTITY_CLUSTERS[address]
                update_list(FP_MITIGATION_CLUSTERS, FP_CLUSTERS_QUEUE_MAX_SIZE, cluster)
                logging.info(f"alert {alert_event.alert_hash} adding FP mitigation cluster: {cluster}. FP mitigation clusters size now: {len(FP_MITIGATION_CLUSTERS)}")
                

    # get alert from base bot and store in DB with time stamp and cluster as the key
    
    if in_list(alert_event, BASE_BOTS):
        return []

    # pull all alerts from DB with the same cluster and check if they are within the time window


    # call model


    # if model says it is a scam, assess for FP mitigation


    # if no FP mitigation, emit scam finding

    except Exception as e:
        logging.warning(f"alert {alert_event.alert_hash} - Exception in process_alert {alert_event.alert_hash}: {e}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"alert {alert_event.alert_hash} - Raising exception to expose error to scannode")
            raise e

    return findings


def provide_handle_block(w3):
    logging.debug("provide_handle_block called")

    def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        logging.debug("handle_block with w3 called")
        return []

    return handle_block


real_handle_block = provide_handle_block(web3)


def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)
