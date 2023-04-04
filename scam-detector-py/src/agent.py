import logging
import sys
import requests
import os
import json
from datetime import datetime
import time
import pandas as pd
import numpy as np
import io
import traceback
import joblib
from hexbytes import HexBytes
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

import forta_agent
from forta_agent import get_json_rpc_url, EntityType
from web3 import Web3

from src.L2Cache import L2Cache
from src.constants import (ENTITY_CLUSTER_BOTS, FP_MITIGATION_BOTS, ALERT_LOOKBACK_WINDOW_IN_DAYS,
                         ENTITY_CLUSTERS_MAX_QUEUE_SIZE,
                         ENTITY_CLUSTERS_KEY, ALERTED_CLUSTERS_LOOSE_KEY, ALERTED_CLUSTERS_STRICT_KEY, ALERTED_FP_CLUSTERS_KEY,
                         MODEL_ALERT_THRESHOLD_LOOSE, MODEL_ALERT_THRESHOLD_STRICT, MODEL_FEATURES, MODEL_NAME, CLUSTER_QUEUE_SIZE)
from src.storage import s3_client, dynamo_table, get_secrets, bucket_name
from src.findings import ScamDetectorFinding
from src.blockchain_indexer_service import BlockChainIndexer

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
block_chain_indexer = BlockChainIndexer()

CHAIN_ID = -1

ENTITY_CLUSTERS = dict()  # address -> cluster
CONTRACT_CACHE = dict()  # address -> is_contract

ALERTED_CLUSTERS_LOOSE = set()  # cluster that have been alerted on
ALERTED_CLUSTERS_STRICT = set()  # cluster that have been alerted on
ALERTED_FP_CLUSTERS = set()  # clusters which are considered FPs that have been alerted on

BASE_BOTS = []

MODEL = None

s3 = None
dynamo = None
item_id_prefix = ""

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

etherscan_label_api = "https://api.forta.network/labels/state?sourceIds=etherscan,0x6f022d4a65f397dffd059e269e1c2b5004d822f905674dbf518d968f744c2ede&entities="

def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global CHAIN_ID
    try:
        CHAIN_ID = os.environ.get('FORTA_CHAIN_ID')
        if CHAIN_ID is None:
            CHAIN_ID = web3.eth.chain_id
        logging.info(f"Set chain id to {CHAIN_ID}")
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e

    global ENTITY_CLUSTERS
    entity_cluster_alerts = load(CHAIN_ID, ENTITY_CLUSTERS_KEY)
    ENTITY_CLUSTERS = {} if entity_cluster_alerts is None else dict(entity_cluster_alerts)

    global ALERTED_CLUSTERS_LOOSE
    alerted_clusters_loose = load(CHAIN_ID, ALERTED_CLUSTERS_LOOSE_KEY)
    ALERTED_CLUSTERS_LOOSE = set() if alerted_clusters_loose is None else set(alerted_clusters_loose)

    global ALERTED_CLUSTERS_STRICT
    alerted_clusters_strict = load(CHAIN_ID, ALERTED_CLUSTERS_STRICT_KEY)
    ALERTED_CLUSTERS_STRICT = set() if alerted_clusters_strict is None else set(alerted_clusters_strict)

    global ALERTED_FP_CLUSTERS
    alerted_fp_addresses = load(CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
    ALERTED_FP_CLUSTERS = set() if alerted_fp_addresses is None else alerted_fp_addresses

    global CONTRACT_CACHE
    CONTRACT_CACHE = {}

    global MODEL
    MODEL = joblib.load(MODEL_NAME)

    # initialize dynamo DB
    global s3, dynamo
    secrets = get_secrets()
    s3 = s3_client(secrets)
    dynamo = dynamo_table(secrets)
    logging.info("Initializing scam detector bot. Initialized dynamo DB successfully.")

    # subscribe to the base bots, FP mitigation and entity clustering bot
    global BASE_BOTS
    subscription_json = []
    for feature in MODEL_FEATURES:
        tokens = feature.split("_")
        if len(tokens) == 2 and tokens[1] != 'count':
            BASE_BOTS.append((tokens[0], tokens[1]))
            subscription_json.append({"botId": tokens[0], "alertId": tokens[1], "chainId": CHAIN_ID})

    for bot, alertId in ENTITY_CLUSTER_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId, "chainId": CHAIN_ID})

    alert_config = {"alertConfig": {"subscriptions": subscription_json}}
    logging.info(f"Initializing scam detector bot. Subscribed to bots successfully: {alert_config}")
    logging.info("Initialized scam detector bot.")
    return alert_config


def is_contract(w3, addresses) -> bool:
    """
    this function determines whether address/ addresses is a contract; if all are contracts, returns true; otherwise false
    :return: is_contract: bool
    """
    global CONTRACT_CACHE

    if addresses is None:
        return True

    if CONTRACT_CACHE.get(addresses) is not None:
        return CONTRACT_CACHE[addresses]
    else:
        is_contract = True
        for address in addresses.split(','):
            code = w3.eth.get_code(Web3.toChecksumAddress(address))
            is_contract = is_contract & (code != HexBytes('0x'))
        CONTRACT_CACHE[addresses] = is_contract
        return is_contract


def in_list(alert_event: forta_agent.alert_event.AlertEvent, bots: tuple) -> bool:
    """
    this function returns True if the alert is from a bot in the bots tuple
    :return: bool
    """
    for tup in bots:
        if alert_event.alert.source.bot.id == tup[0] and alert_event.alert.alert_id == tup[1]:
            return True

    return False

def get_fp_mitigation_bot_labels(cluster: str) -> str:
    if cluster is None:
        return []
    
    label_api = "https://api.forta.network/labels/state?sourceIds="
    fp_mitigation_bot_ids = set()
    for bot_id, alert_id in FP_MITIGATION_BOTS:
        fp_mitigation_bot_ids.add(bot_id)
    label_api += ",".join(fp_mitigation_bot_ids)
    label_api += "&entities=" + cluster.lower() # already comma separated

    label_strs = []
    try:
        res = requests.get(label_api)  
        if res.status_code == 200:
            labels = res.json()
            if len(labels) > 0:
                for i in range(len(labels)):
                    logging.info(f"retreived label for {cluster}: {labels['events'][i]}")
                    if 'benign' in labels['events'][i]['label']['label'].lower():
                        label_strs.append(labels['events'][i]['label']['label'])

    except Exception as e:
        logging.warning(f"Exception in get_fp_mitigation_bot_labels {e}")
    
    return label_strs
    
    
def get_etherscan_label(cluster: str) -> list:
    if cluster is None:
        return ""

    labels_str = []    
    try:
        res = requests.get(etherscan_label_api + cluster.lower())  # already comma separated
        if res.status_code == 200:
            labels = res.json()
            if len(labels) > 0 and labels['events'] is not None:
                logging.info(f"retreived label for {cluster}: {labels['events'][0]}")
                labels_str.append(labels['events'][0]['label']['label'])
    except Exception as e:
        logging.warning(f"Exception in get_etherscan_label {e}")
    
    return labels_str

def update_list(items: set, max_size: int, item: str):

    items.add(item.lower())

    while len(items) > max_size:
        items.pop(0)  # remove oldest item


def get_total_shards() -> int:
    logging.debug("getting total shards")
    package = json.load(open("package.json"))
    logging.debug("loaded package.json")
    logging.debug(f"getting shard count for chain id {CHAIN_ID}")
    if str(CHAIN_ID) in package["chainSettings"]:   
        logging.debug(f"have specific shard count value for chain id {CHAIN_ID}")
        total_shards = package["chainSettings"][str(CHAIN_ID)]["shards"]
    else:
        logging.debug(f"have specific shard count value for default")
        total_shards = package["chainSettings"]["default"]["shards"]
    logging.debug(f"total shards: {total_shards}")
    return total_shards
    

def get_shard(timestamp: int) -> int:
    logging.debug(f"getting shard for timestamp {timestamp}")
    total_shards = get_total_shards()
    shard = int(timestamp % total_shards)
    logging.debug(f"shard: {shard}")
    return shard


# put in item alerts per cluster by shard id
# note, given sort key is part of the key, alerts with different hashes will result in different entries
# whereas alerts with the same hash will be overwritten
def put_alert(alert_event: forta_agent.alert_event.AlertEvent, cluster: str):
    logging.debug(f"putting alert {alert_event.alert_hash} in dynamo DB")
    alert_created_at_str = alert_event.alert.created_at
    alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
    logging.debug(f"alert_created_at: {alert_created_at}")
    shard = get_shard(alert_created_at)
    logging.debug(f"shard: {shard}")
    itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|alert|{cluster}"
    logging.debug(f"itemId: {itemId}")
    sortId = f"{alert_event.alert.source.bot.id}|{alert_event.alert.alert_id}|{alert_event.alert_hash}"
    logging.debug(f"sortId: {sortId}")
    
    expiry_offset = ALERT_LOOKBACK_WINDOW_IN_DAYS * 24 * 60 * 60
    
    expiresAt = int(alert_created_at) + int(expiry_offset)
    logging.debug(f"expiresAt: {expiresAt}")
    response = dynamo.put_item(Item={
        "itemId": itemId,
        "sortKey": sortId,
        "botId": alert_event.alert.source.bot.id,
        "alertId": alert_event.alert.alert_id,
        "alertHash": alert_event.alert_hash,
        "cluster": cluster,
        "expiresAt": expiresAt
    })

    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logging.error(f"Error putting alert in dynamoDB: {response}")
        return
    else:
        logging.info(f"Successfully put alert in dynamoDB: {response}")
        return


def read_alerts(cluster: str) -> list:
    logging.debug(f"Reading alerts for cluster {cluster}")
    alert_items = []
    for shard in range(get_total_shards()):
        itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|alert|{cluster}"
        logging.debug(f"Reading alerts for cluster {cluster} from shard {shard}, itemId {itemId}")
        logging.debug(f"Dynamo : {dynamo}")
        response = dynamo.query(KeyConditionExpression='itemId = :id',
                                ExpressionAttributeValues={
                                    ':id': itemId
                                }
                                )

        # Print retrieved item
        items = response.get('Items', [])
        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            alert_items.append((item["botId"], item["alertId"], item["alertHash"]))
    logging.info(f"Read alerts for cluster {cluster}. Retrieved {len(alert_items)} alerts.")
    return alert_items

# TODO - bring in line with training scripts
def get_scammer_addresses(alert_event: forta_agent.alert_event.AlertEvent) -> set:
    scammer_addresses = set()
    for label in alert_event.alert.labels:
        label_lower = label.label.lower()
        if ("scam" in label_lower or "attack" in label_lower) and label.entity_type == EntityType.Address:
            scammer_addresses.add(label.entity.lower())

    if alert_event.alert.metadata is not None:
        for key in ["attackerAddresses", "attacker_address"]:
            if key in alert_event.alert.metadata.keys(): # address poisoning bot
                attacker_addresses = alert_event.alert.metadata[key]
                for attacker_address in attacker_addresses.split(','):
                    scammer_addresses.add(attacker_address.lower())

    return scammer_addresses

# alerts are tuples of (botId, alertId, alertHash)
def build_feature_vector(alerts: list, cluster: str) -> pd.DataFrame: 
    df_feature_vector = pd.DataFrame(columns=MODEL_FEATURES)
    df_feature_vector.loc[0] = np.zeros(len(MODEL_FEATURES))

    # create dataframe out of list of alert tuples
    df_alerts_all = pd.DataFrame(alerts, columns=['bot_id', 'alert_id', 'alert_hash'])
    df_alerts_all.drop_duplicates(inplace=True)
    df_alerts_all['cluster'] = cluster
    df_alerts_all['alert_hash'] = 1


    grouped = df_alerts_all.groupby(['cluster', 'bot_id', 'alert_id'])['alert_hash'].sum().reset_index()
    pivoted = pd.pivot_table(grouped, values='alert_id', index = 'cluster', columns=['bot_id', 'alert_id'], aggfunc='sum')
    pivoted.columns = [f'{col[0]}_{col[1]}' for col in pivoted.columns]
    pivoted.fillna(0, inplace=True)


    bot_count_features = set()
    for column in pivoted.columns:
        bot_count_features.add(column[0:66])

    for bot_count_feature in bot_count_features:
        pivoted[bot_count_feature + '_count'] = 0

    for index, row in pivoted.iterrows():
        for column in pivoted.columns:
            if column[0:66] in bot_count_features and column[0:66] + '_count' not in column:
                count = row[column]
                pivoted.loc[index, column[0:66] + '_count'] += count


    for column in pivoted.columns:
        df_feature_vector.loc[0, column] = pivoted.loc[cluster, column]

    df_feature_vector = df_feature_vector.sort_index(axis=1) #sort columns alphabetically
    return df_feature_vector

def get_model_score(df_feature_vector: pd.DataFrame) -> float:
    global MODEL
    logging.debug(f"Feature vector: {df_feature_vector.loc[0]}")

    predictions_proba = MODEL.predict_proba(df_feature_vector)[:, 1]
    return predictions_proba
    
def is_fp(cluster: str) -> bool:
    etherscan_label = ','.join(get_etherscan_label(cluster)).lower()
    if not ('attack' in etherscan_label
            or 'phish' in etherscan_label
            or 'hack' in etherscan_label
            or 'heist' in etherscan_label
            or 'exploit' in etherscan_label
            or 'scam' in etherscan_label
            or 'fraud' in etherscan_label
            or etherscan_label == ''):
        return True
    
    fp_mitigation_bot_labels = get_fp_mitigation_bot_labels(cluster)
    for label in fp_mitigation_bot_labels:
        if 'benign' in label.lower():
            return True
    
    return False


def detect_scam(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    
    global ENTITY_CLUSTERS
    global ENTITY_CLUSTER_BOTS
    global ENTITY_CLUSTERS_MAX_QUEUE_SIZE
    global CHAIN_ID
    global ALERTED_CLUSTERS_STRICT
    global ALERTED_CLUSTERS_LOOSE
    global BASE_BOTS

    
    findings = []
    try:
        start = time.time()

        if CHAIN_ID == -1:
            logging.error("CHAIN_ID not set")
            raise Exception("CHAIN_ID not set")

        chain_id = int(alert_event.alert.source.block.chain_id) if alert_event.alert.source.block.chain_id is not None else int(alert_event.chain_id)
        if chain_id == CHAIN_ID:
            # got alert from the right chain

            # TODO - change to using dynamo as the bot shards
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

                    # TODO - read all entries from dynamoDB and update entries for cluster



            # for basebots, store in dynamo; then query dynamo for the cluster (this will pull all alerts from multiple shards), build feature vector and then call the model for inference
            if in_list(alert_event, BASE_BOTS):
                scammer_addresses_lower = get_scammer_addresses(alert_event)
                logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got base bot alert; extracted {len(scammer_addresses_lower)} scammer addresses.")
                for scammer_address_lower in scammer_addresses_lower:
                    cluster = scammer_address_lower
                    if scammer_address_lower in ENTITY_CLUSTERS.keys():
                        cluster = ENTITY_CLUSTERS[scammer_address_lower]
                    logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got alert for cluster {cluster}")

                    if is_contract(w3, cluster):
                        logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} is contract, skipping")
                        continue

                    if cluster in ALERTED_CLUSTERS_STRICT:
                        logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} already alerted on (strict); skipping")
                        continue

                    put_alert(alert_event, cluster)

                    # get all alerts from dynamo for the cluster
                    alerts = read_alerts(cluster)  # list of tuple of (botId, alertId, alertHash)
                    logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got {len(alerts)} alerts from dynamo for cluster {cluster}")

                    # build feature vector
                    feature_vector = build_feature_vector(alerts, cluster)

                    # # call model
                    score = get_model_score(feature_vector)
                    logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - model score for {cluster}: {score}")

                    # if model says it is a scam, assess for FP mitigation
                    if score > MODEL_ALERT_THRESHOLD_STRICT:
                        logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - model score {score} > {MODEL_ALERT_THRESHOLD_STRICT} (strict) for cluster {cluster}")
                        # if cluster not an FP, emit scam finding
                        if not is_fp(cluster):
                            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
                            findings.append(ScamDetectorFinding.scam_finding_model(block_chain_indexer, cluster, score, "SCAM-DETECTOR-MODEL-1", feature_vector, alerts, chain_id))
                            update_list(ALERTED_CLUSTERS_STRICT, CLUSTER_QUEUE_SIZE, cluster)
                            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
                        else:
                            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} in FP.")
                    elif score > MODEL_ALERT_THRESHOLD_LOOSE and cluster not in ALERTED_CLUSTERS_LOOSE:
                        logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - model score {score} > {MODEL_ALERT_THRESHOLD_LOOSE} (loose) for cluster {cluster}")
                        # if cluster not an FP, emit scam finding
                        if not is_fp(cluster):
                            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
                            findings.append(ScamDetectorFinding.scam_finding_model(block_chain_indexer, cluster, score, "SCAM-DETECTOR-MODEL-2", feature_vector, alerts, chain_id))
                            update_list(ALERTED_CLUSTERS_LOOSE, CLUSTER_QUEUE_SIZE, cluster)
                            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
                        else:
                            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} in FP.")

        end = time.time()
        logging.info(f"alert {alert_event.alert_hash} {alert_event.alert_id} {alert_event.chain_id} processing took {end - start} seconds")
    except Exception as e:
        logging.warning(f"alert {alert_event.alert_hash} - Exception in process_alert {alert_event.alert_hash}: {e} - {traceback.format_exc()}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"alert {alert_event.alert_hash} - Raising exception to expose error to scannode")
            raise e

    return findings


def emit_new_fp_finding(w3) -> list:
    global ALERTED_FP_CLUSTERS
    global CLUSTER_QUEUE_SIZE
    global CHAIN_ID
    findings = []

    if CHAIN_ID == -1:
        logging.error("Chain ID not set")
        raise Exception("Chain ID not set")

    res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/Scam-Detector-ML/scam-detector-py/fp_list.tsv')
    content = res.content.decode('utf-8') if res.status_code == 200 else open('fp_list.tsv', 'r').read()
    df_fp = pd.read_csv(io.StringIO(content), sep='\t')
    for index, row in df_fp.iterrows():
        chain_id = int(row['chain_id'])
        if chain_id != CHAIN_ID:
            continue
        cluster = row['cluster'].lower()
        if cluster not in ALERTED_FP_CLUSTERS:
            logging.info("Emitting FP mitigation finding")
            update_list(ALERTED_FP_CLUSTERS, CLUSTER_QUEUE_SIZE, cluster)
            findings.append(ScamDetectorFinding.alert_FP(cluster))
            logging.info(f"Findings count {len(findings)}")
            persist_state()

    return findings


def emit_manual_finding(w3) -> list:
    global ALERTED_CLUSTERS_STRICT
    global ENTITY_CLUSTERS
    global CHAIN_ID
    global CLUSTER_QUEUE_SIZE
    findings = []

    if CHAIN_ID == -1:
        logging.error("Chain ID not set")
        raise Exception("Chain ID not set")

    res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/Scam-Detector-ML/scam-detector-py/manual_alert_list.tsv')
    logging.info(f"made request to fetch manual alerts: {res.status_code}")
    content = res.content.decode('utf-8') if res.status_code == 200 else open('manual_alert_list.tsv', 'r').read()
    df_manual_findings = pd.read_csv(io.StringIO(content), sep='\t')
    for index, row in df_manual_findings.iterrows():
        logging.info("Reading manual finding")
        chain_id = -1
        try:
            chain_id_float = row['Chain ID']
            chain_id = int(chain_id_float)
        except:
            logging.warn("Failed to get chain ID from manual finding")
            continue

        if chain_id != CHAIN_ID:
            continue

        address_lower = row['Address'].lower()
        cluster = address_lower
        if address_lower in ENTITY_CLUSTERS.keys():
            cluster = ENTITY_CLUSTERS[address_lower]

        if cluster not in ALERTED_CLUSTERS_STRICT:
            logging.info("Emitting manual finding")
            update_list(ALERTED_CLUSTERS_STRICT, CLUSTER_QUEUE_SIZE, cluster)
            findings.append(ScamDetectorFinding.scam_finding_manual(block_chain_indexer, cluster, row['Threat category'], row['Account'] + " " + row['Tweet'], chain_id))
            logging.info(f"Findings count {len(findings)}")
            persist_state()

    return findings




def persist_state():
    global ALERTED_CLUSTERS_LOOSE_KEY
    global ALERTED_CLUSTERS_STRICT_KEY
    global ALERTED_FP_CLUSTERS_KEY
    global ENTITY_CLUSTERS_KEY

    global ALERTED_CLUSTERS_LOOSE
    global ALERTED_CLUSTERS_STRICT
    global ALERTED_FP_CLUSTERS
    global ENTITY_CLUSTERS

    global CHAIN_ID

    start = time.time()
    persist(ENTITY_CLUSTERS, CHAIN_ID, ENTITY_CLUSTERS_KEY)
    persist(ALERTED_CLUSTERS_LOOSE, CHAIN_ID, ALERTED_CLUSTERS_LOOSE_KEY)
    persist(ALERTED_CLUSTERS_STRICT, CHAIN_ID, ALERTED_CLUSTERS_STRICT_KEY)
    persist(ALERTED_FP_CLUSTERS, CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)

    end = time.time()
    logging.info(f"Persisted bot state. took {end - start} seconds")


def persist(obj: object, chain_id: int, key: str):
    L2Cache.write(obj, chain_id, key)


def load(chain_id: int, key: str) -> object:
    return L2Cache.load(chain_id, key)


def provide_handle_alert(w3):
    logging.debug("provide_handle_alert called")

    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        logging.debug("handle_alert inner called")

        findings = detect_scam(w3, alert_event)
        if not ('NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV')):
            persist_state()

        return findings

    return handle_alert


real_handle_alert = provide_handle_alert(web3)

def provide_handle_block(w3):
    logging.debug("provide_handle_block called")

    def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        logging.debug("handle_block with w3 called")
        findings = []
        if datetime.now().minute == 0:  # every hour
            persist_state()
            findings.extend(emit_new_fp_finding(w3))
            findings.extend(emit_manual_finding(w3))
        return findings

    return handle_block


real_handle_block = provide_handle_block(web3)

def handle_alert(alert_event: forta_agent.alert_event.AlertEvent):
    logging.debug("handle_alert called")
    return real_handle_alert(alert_event)

def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)
