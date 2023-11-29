import logging
import sys
import requests
import os
from datetime import datetime, timedelta
import time
import pandas as pd
import numpy as np
import io
import re
import json
import math
import pytz
import traceback
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

import forta_agent
from forta_agent import Finding, FindingType, FindingSeverity, get_alerts, get_labels
from web3 import Web3

from src.constants import (BASE_BOTS, ALERTED_ENTITIES_ML_KEY, ALERTED_ENTITIES_ML_QUEUE_SIZE, ALERTED_ENTITIES_PASSTHROUGH_KEY, ALERTED_ENTITIES_PASSTHROUGH_QUEUE_SIZE, ALERTED_ENTITIES_SCAMMER_ASSOCIATION_KEY, ALERTED_ENTITIES_SCAMMER_ASSOCIATION_QUEUE_SIZE, ALERTED_ENTITIES_SIMILAR_CONTRACT_KEY, ALERTED_ENTITIES_SIMILAR_CONTRACT_QUEUE_SIZE, ALERTED_ENTITIES_MANUAL_KEY, ALERTED_ENTITIES_MANUAL_QUEUE_SIZE, ALERTED_ENTITIES_MANUAL_METAMASK_KEY, ALERTED_ENTITIES_MANUAL_METAMASK_QUEUE_SIZE, ALERT_LOOKBACK_WINDOW_IN_DAYS, ENTITY_CLUSTER_BOTS,
                       FINDINGS_CACHE_ALERT_KEY, FINDINGS_CACHE_BLOCK_KEY, ALERTED_FP_CLUSTERS_KEY, FINDINGS_CACHE_TRANSACTION_KEY,
                       ALERTED_FP_CLUSTERS_QUEUE_SIZE, SCAM_DETECTOR_BOT_ID, SCAM_DETECTOR_BETA_BOT_ID, SCAM_DETECTOR_BETA_ALT_BOT_ID, CONTRACT_SIMILARITY_BOTS, CONTRACT_SIMILARITY_BOT_THRESHOLDS, EOA_ASSOCIATION_BOTS,
                       EOA_ASSOCIATION_BOT_THRESHOLDS, PAIRCREATED_EVENT_ABI, SWAP_FACTORY_ADDRESSES, POOLCREATED_EVENT_ABI, ENCRYPTED_BOTS,
                       MODEL_ALERT_THRESHOLD_LOOSE, MODEL_ALERT_THRESHOLD_STRICT, MODEL_FEATURES, MODEL_NAME, DEBUG_ALERT_ENABLED, ENABLE_METAMASK_CONSUMPTION)
from src.storage import s3_client, dynamo_table, get_secrets, bucket_name
from src.findings import ScamDetectorFinding
from src.blockchain_indexer_service import BlockChainIndexer
from src.forta_explorer import FortaExplorer
from src.base_bot_parser import BaseBotParser
from src.l2_cache import L2Cache
from src.utils import Utils

web3 = Utils.get_rpc_endpoint()
block_chain_indexer = BlockChainIndexer()
forta_explorer = FortaExplorer()

INITIALIZED = False
INITIALIZED_CALLED = False
INITIAL_METAMASK_LIST_CONSUMPTION = True
INITIALIZATION_TIME = datetime.now()
CHAIN_ID = -1
BOT_VERSION = Utils.get_bot_version()
LAST_PROCESSED_TIME = 0 # Used to update reactive likely fps

ALERTED_ENTITIES_ML = dict()  # cluster -> alert_id
ALERTED_ENTITIES_PASSTHROUGH = dict()  # cluster -> alert_id
ALERTED_ENTITIES_SCAMMER_ASSOCIATION = dict()  # cluster -> alert_id
ALERTED_ENTITIES_SIMILAR_CONTRACT = dict()  # cluster -> alert_id
ALERTED_ENTITIES_MANUAL = dict()  # cluster -> alert_id
ALERTED_ENTITIES_MANUAL_METAMASK = dict()  # cluster -> alert_id
ALERTED_ENTITIES_MANUAL_METAMASK_LIST = [] # Used to reduce size of persisted item
ALERTED_FP_CLUSTERS = dict()  # clusters -> alert_id (dummy val) which are considered FPs that have been alerted on
FINDINGS_CACHE_BLOCK = []
FINDINGS_CACHE_ALERT = []
FINDINGS_CACHE_TRANSACTION = []
REACTIVE_LIKELY_FPS = {}  # address -> list of label metadata (addresses that are yet to be checked)
SCAMMER_ASSOCIATION_LABELS = None
SIMILAR_CONTRACT_LABELS = None
DF_CONTRACT_SIGNATURES = None

MODEL = None

s3 = None
dynamo = None
secrets = None
item_id_prefix = ""

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)



def initialize(test = False):
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    if test:
        Utils.TEST_STATE = True
    
    global INITIALIZED_CALLED
    INITIALIZED_CALLED = True

    alert_config = {}
    global INITIALIZED

    try:
        reinitialize()

        global ALERTED_ENTITIES_ML
        alerted_entities_ml = load(CHAIN_ID, ALERTED_ENTITIES_ML_KEY)
        ALERTED_ENTITIES_ML = dict() if alerted_entities_ml is None else dict(alerted_entities_ml)

        global ALERTED_ENTITIES_PASSTHROUGH
        alerted_entities_passthrough = load(CHAIN_ID, ALERTED_ENTITIES_PASSTHROUGH_KEY)
        ALERTED_ENTITIES_PASSTHROUGH = dict() if alerted_entities_passthrough is None else dict(alerted_entities_passthrough)

        global ALERTED_ENTITIES_SCAMMER_ASSOCIATION
        alerted_entities_scammer_association = load(CHAIN_ID, ALERTED_ENTITIES_SCAMMER_ASSOCIATION_KEY)
        ALERTED_ENTITIES_SCAMMER_ASSOCIATION = dict() if alerted_entities_scammer_association is None else dict(alerted_entities_scammer_association)

        global ALERTED_ENTITIES_SIMILAR_CONTRACT
        alerted_entities_similar_contract = load(CHAIN_ID, ALERTED_ENTITIES_SIMILAR_CONTRACT_KEY)
        ALERTED_ENTITIES_SIMILAR_CONTRACT = dict() if alerted_entities_similar_contract is None else dict(alerted_entities_similar_contract)

        global ALERTED_ENTITIES_MANUAL
        alerted_entities_manual = load(CHAIN_ID, ALERTED_ENTITIES_MANUAL_KEY)
        ALERTED_ENTITIES_MANUAL = dict() if alerted_entities_manual is None else dict(alerted_entities_manual)

        if CHAIN_ID == 1:
            global ALERTED_ENTITIES_MANUAL_METAMASK
            global ALERTED_ENTITIES_MANUAL_METAMASK_LIST
            alerted_entities_manual_metamask = load(CHAIN_ID, ALERTED_ENTITIES_MANUAL_METAMASK_KEY)
            ALERTED_ENTITIES_MANUAL_METAMASK_LIST = [] if alerted_entities_manual_metamask is None else list(alerted_entities_manual_metamask)
            ALERTED_ENTITIES_MANUAL_METAMASK = {item: 'manual_metamaskSCAM-DETECTOR-MANUAL-METAMASK-PHISHING' for item in ALERTED_ENTITIES_MANUAL_METAMASK_LIST}

        global ALERTED_FP_CLUSTERS
        alerted_fp_addresses = load(CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
        ALERTED_FP_CLUSTERS = dict() if alerted_fp_addresses is None else dict(alerted_fp_addresses)

        global FINDINGS_CACHE_BLOCK
        findings_cache_block = load(CHAIN_ID, FINDINGS_CACHE_BLOCK_KEY)
        FINDINGS_CACHE_BLOCK = [] if findings_cache_block is None else list(findings_cache_block)

        global FINDINGS_CACHE_ALERT
        findings_cache_alert = load(CHAIN_ID, FINDINGS_CACHE_ALERT_KEY)
        FINDINGS_CACHE_ALERT = [] if findings_cache_alert is None else list(findings_cache_alert)

        global FINDINGS_CACHE_TRANSACTION
        findings_cache_transaction = load(CHAIN_ID, FINDINGS_CACHE_TRANSACTION_KEY)
        FINDINGS_CACHE_TRANSACTION = [] if findings_cache_transaction is None else list(findings_cache_transaction)
        
        global DF_CONTRACT_SIGNATURES
        df_manual_list = Utils.get_manual_list()
        DF_CONTRACT_SIGNATURES = df_manual_list[df_manual_list['EntityType']=='Code']

        global MODEL
        MODEL = joblib.load(MODEL_NAME)

        # subscribe to the base bots, FP mitigation and entity clustering bot
        global BASE_BOTS
        subscription_json = []
        for botId, alertId, alert_logic, target_alert_id in BASE_BOTS:
            subscription_json.append({"botId": botId, "alertId": alertId, "chainId": CHAIN_ID})

        alert_config = {"alertConfig": {"subscriptions": subscription_json}}
        logging.info(f"{BOT_VERSION}: Initializing scam detector bot. Subscribed to bots successfully: {alert_config}")
        logging.info(f"{BOT_VERSION}: Initialized scam detector bot.")
        INITIALIZED = True
    except Exception as e:
        logging.error(f"{BOT_VERSION}: Error initializing scam detector bot: {e}")
        raise e

    return alert_config


def reinitialize():
    global CHAIN_ID
    global BOT_VERSION
    global s3
    global dynamo
    global secrets 

    try:
        # initialize dynamo DB
        if dynamo is None:
            secrets = get_secrets()
            s3 = s3_client(secrets)
            dynamo = dynamo_table(secrets)
            logging.info(f"{BOT_VERSION}: Initialized dynamo DB successfully.")
    except Exception as e:
        logging.error(f"{BOT_VERSION}: Error getting chain id: {e}")
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
  

def in_list(alert_event: forta_agent.alert_event.AlertEvent, bots: tuple) -> bool:
    """
    this function returns True if the alert is from a bot in the bots tuple
    :return: bool
    """
    for tup in bots:
        if alert_event.alert.source.bot.id == tup[0] and alert_event.alert.alert_id == tup[1]:
            return True

    return False


def alert_logic(alert_event: forta_agent.alert_event.AlertEvent, bots: tuple) -> str:
    """
    this function returns True if the alert is from a bot in the bots tuple
    :return: bool
    """
    for tup in bots:
        if alert_event.alert.source.bot.id == tup[0] and alert_event.alert.alert_id == tup[1]:
            return tup[2]

    return ""

def alert_target(alert_event: forta_agent.alert_event.AlertEvent, bots: tuple) -> str:
    """
    this function returns True if the alert is from a bot in the bots tuple
    :return: bool
    """
    for tup in bots:
        if alert_event.alert.source.bot.id == tup[0] and alert_event.alert.alert_id == tup[1]:
            return tup[3]

    return ""


def update_list(items: dict, max_size: int, item: str, alert_id: str, logic = ""):
    if item not in items.keys():
        items[item] = set()
    items[item].add(logic+alert_id)


    while len(items) > max_size:
        items.pop(0)  # remove oldest item


def put_entity_cluster(alert_created_at_str: str, address: str, cluster: str):
    global CHAIN_ID
    global BOT_VERSION

    logging.debug(f"putting entity clustering alert for {address} in dynamo DB")
    alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
    logging.debug(f"alert_created_at: {alert_created_at}")
    itemId = f"{item_id_prefix}|{CHAIN_ID}|entity_cluster|{address}"
    logging.debug(f"itemId: {itemId}")
    sortId = f"{address}"
    logging.debug(f"sortId: {sortId}")
    
    expiry_offset = ALERT_LOOKBACK_WINDOW_IN_DAYS * 24 * 60 * 60
    
    expiresAt = int(alert_created_at) + int(expiry_offset)
    logging.debug(f"expiresAt: {expiresAt}")
    response = dynamo.put_item(Item={
        "itemId": itemId,
        "sortKey": sortId,
        "address": address,
        "cluster": cluster,
        "expiresAt": expiresAt
    })

    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logging.error(f"Error putting alert in dynamoDB: {response}")
        Utils.ERROR_CACHE.add(Utils.alert_error(f'dynamo.put_item HTTPStatusCode {response["ResponseMetadata"]["HTTPStatusCode"]}', "agent.put_entity_cluster", ""))
        return
    else:
        logging.info(f"Successfully put alert in dynamoDB: {response}")
        return

# put in item alerts per cluster
# note, given sort key is part of the key, alerts with different hashes will result in different entries
# whereas alerts with the same hash will be overwritten
def put_alert(alert_event: forta_agent.alert_event.AlertEvent, cluster: str):
    global CHAIN_ID
    global BOT_VERSION

    logging.debug(f"putting alert {alert_event.alert_hash} in dynamo DB")
    alert_created_at_str = alert_event.alert.created_at
    alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
    logging.debug(f"alert_created_at: {alert_created_at}")
    itemId = f"{item_id_prefix}|{CHAIN_ID}|alert|{cluster}"
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
        Utils.ERROR_CACHE.add(Utils.alert_error(f'dynamo.put_item HTTPStatusCode {response["ResponseMetadata"]["HTTPStatusCode"]}', "agent.put_alert", ""))
        return
    else:
        logging.info(f"Successfully put alert in dynamoDB: {response}")
        return



def read_entity_clusters(address: str) -> dict:
    global CHAIN_ID

    entity_clusters = dict()
    itemId = f"{item_id_prefix}|{CHAIN_ID}|entity_cluster|{address}"
    logging.debug(f"Reading entity clusters for address {address} from itemId {itemId}")
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
        entity_clusters[address] = item["cluster"]
    logging.info(f"Read entity clusters for address {address}. Retrieved {len(entity_clusters)} alert_clusters.")
    return entity_clusters

def read_alerts(cluster: str) -> list:
    global CHAIN_ID
    global BOT_VERSION

    logging.debug(f"Reading alerts for cluster {cluster}")
    alert_items = []
    itemId = f"{item_id_prefix}|{CHAIN_ID}|alert|{cluster}"
    logging.debug(f"Reading alerts for cluster {cluster} from itemId {itemId}")
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

    logging.info(f"{BOT_VERSION}: Read alerts for cluster {cluster}. Retrieved {len(alert_items)} alerts.")
    return alert_items

# alerts are tuples of (botId, alertId, alertHash)
def build_feature_vector(alerts: list, cluster: str) -> pd.DataFrame: 
    global BOT_VERSION

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
        if column in MODEL_FEATURES:
            bot_count_features.add(column[0:66])

    for bot_count_feature in bot_count_features:
        pivoted[bot_count_feature + '_count'] = 0
        pivoted[bot_count_feature + '_uniqalertid_count'] = 0

    for index, row in pivoted.iterrows():
        bot_id_unique_alert_ids = {}
        for column in pivoted.columns:
            if column[0:66] in bot_count_features and column[0:66] + '_count' not in column and column in MODEL_FEATURES:
                count = row[column]
                pivoted.loc[index, column[0:66] + '_count'] += count

                #increment unique alert id count if count > 0
                if column[0:66] not in bot_id_unique_alert_ids:
                    bot_id_unique_alert_ids[column[0:66]] = 0

                if count > 0 and "_count" not in column:
                    bot_id_unique_alert_ids[column[0:66]] += 1


        for column in pivoted.columns:
            if "_uniqalertid_count" in column:
                pivoted.loc[index, column] = bot_id_unique_alert_ids[column[0:66]]


    for column in pivoted.columns:
        df_feature_vector.loc[0, column] = pivoted.loc[cluster, column]

    df_feature_vector = df_feature_vector.sort_index(axis=1) #sort columns alphabetically

    for column in df_feature_vector.columns:
        if column not in MODEL_FEATURES:
            logging.warning(f"Feature {column} not in model features. Dropping.")
            df_feature_vector.drop(columns=[column], inplace=True)

    return df_feature_vector

def get_model_score(df_feature_vector: pd.DataFrame) -> float:
    global MODEL
    global BOT_VERSION

    logging.debug(f"Feature vector: {df_feature_vector.loc[0]}")
    predictions_proba = MODEL.predict_proba(df_feature_vector)[:, 1]

    return predictions_proba[0]


def already_alerted(entity: str, alert_id: str, logic = ""):
    global ALERTED_ENTITIES_ML, ALERTED_ENTITIES_PASSTHROUGH, ALERTED_ENTITIES_SCAMMER_ASSOCIATION, ALERTED_ENTITIES_SIMILAR_CONTRACT, ALERTED_ENTITIES_MANUAL, ALERTED_ENTITIES_MANUAL_METAMASK
    
    if logic == "ml":
        alerted_entities = ALERTED_ENTITIES_ML
    elif logic == "passthrough":
        alerted_entities = ALERTED_ENTITIES_PASSTHROUGH
    elif logic == "scammer_association":
        alerted_entities = ALERTED_ENTITIES_SCAMMER_ASSOCIATION
    elif logic == "similar_contract":
        alerted_entities = ALERTED_ENTITIES_SIMILAR_CONTRACT
    elif logic == "manual":
        alerted_entities = ALERTED_ENTITIES_MANUAL
    elif logic == "manual_metamask":
        alerted_entities = ALERTED_ENTITIES_MANUAL_METAMASK   
    
    if entity in alerted_entities.keys():
        if (logic+alert_id) in alerted_entities[entity]:
            return True
    return False

def get_scam_detector_alert_ids(alert_list: list) -> set:
    global BASE_BOTS

    scam_detector_alert_ids = set()
    base_bots_set = {(botId, alertId) for botId, alertId, _, _ in BASE_BOTS}
    alert_list_set = {(botId, alertId) for botId, alertId, _ in alert_list}
    for botId, alertId in base_bots_set.intersection(alert_list_set):
        for botId1, alertId1, _, target_alert_id in BASE_BOTS:
            if target_alert_id is not None and target_alert_id != "":
                if botId == botId1 and alertId == alertId1:
                    scam_detector_alert_ids.add(target_alert_id)

    return scam_detector_alert_ids


def emit_ml_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    findings = []
    global ALERTED_ENTITIES_ML
    global ALERTED_ENTITIES_ML_QUEUE_SIZE
    global BASE_BOTS
    global CHAIN_ID
    global BOT_VERSION

    start_time = time.time()

    scammer_addresses_dict = BaseBotParser.get_scammer_addresses(w3, alert_event)
    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got base bot alert (combination); extracted {len(scammer_addresses_dict.keys())} scammer addresses. Processing took {time.time() - start_time} seconds.")
    for scammer_address in scammer_addresses_dict.keys():
        scammer_address_lower = scammer_address.lower()
        scammer_contract_addresses = scammer_addresses_dict[scammer_address]['scammer-contracts'] if 'scammer-contracts' in scammer_addresses_dict[scammer_address] else set()
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got scammer address {scammer_address_lower}")
        cluster = scammer_address_lower
        entity_cluster = read_entity_clusters(scammer_address_lower)
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - read {len(entity_cluster.keys())} clusters for scammer address {scammer_address_lower}. Processing took {time.time() - start_time} seconds.")
        if scammer_address_lower in entity_cluster.keys():
            cluster = entity_cluster[scammer_address_lower]
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got alert for cluster {cluster}")

        if Utils.is_contract(w3, cluster):
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} is contract, skipping")
            continue
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - {scammer_address_lower} is not a contract. Processing took {time.time() - start_time} seconds.")

        put_alert(alert_event, cluster)
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - put alert into dynamo for cluster {cluster}. Processing took {time.time() - start_time} seconds.")

        # get all alerts from dynamo for the cluster
        alert_list = read_alerts(cluster)  # list of tuple of (botId, alertId, alertHash)
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got {len(alert_list)} alerts from dynamo for cluster {cluster}. Processing took {time.time() - start_time} seconds.")


        # assess based on ML model
        feature_vector = build_feature_vector(alert_list, cluster)
        score = get_model_score(feature_vector)
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got score {score} for cluster {cluster}. Processing took {time.time() - start_time} seconds.")
        model_threshold = MODEL_ALERT_THRESHOLD_LOOSE if (Utils.is_beta() or Utils.is_beta_alt()) else MODEL_ALERT_THRESHOLD_STRICT
        logging.info(f"{BOT_VERSION}: model threshold {model_threshold}.")
        if score>model_threshold:
            #since this is a expensive function, will only check if we are about to raise an alert
            if Utils.is_fp(w3, cluster, CHAIN_ID):
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} identified as FP; skipping")
                continue

            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters. Processing took {time.time() - start_time} seconds.")
            for alert_id in get_scam_detector_alert_ids(alert_list):

                unique_alertIds = set(alert[1] for alert in alert_list)
                unique_alertHashes = set(alert[2] for alert in alert_list)
                created_at_datetime = datetime.strptime(alert_event.alert.created_at[0:19], "%Y-%m-%dT%H:%M:%S")
                if already_alerted(cluster, alert_id, "ml"):  
                    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} already alerted on for {alert_id}; skipping")
                else:
                    metadata = scammer_addresses_dict[scammer_address]
                    findings.append(ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, scammer_address_lower, created_at_datetime, created_at_datetime, scammer_contract_addresses, alert_event.alert.addresses, unique_alertIds, alert_id, unique_alertHashes, metadata, CHAIN_ID, "ml", score, feature_vector))
                    update_list(ALERTED_ENTITIES_ML, ALERTED_ENTITIES_ML_QUEUE_SIZE, cluster, alert_id, "ml")
                
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} added to findings. Findings size: {len(findings)}")

    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - return total findings: {len(findings)}. Processing took {time.time() - start_time} seconds.")
    return findings

def emit_passthrough_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    findings = []
    global ALERTED_ENTITIES_PASSTHROUGH
    global ALERTED_ENTITIES_PASSTHROUGH_QUEUE_SIZE
    global BASE_BOTS
    global CHAIN_ID

    scammer_addresses_dict = BaseBotParser.get_scammer_addresses(w3, alert_event)
    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got base bot alert (passthrough); extracted {len(scammer_addresses_dict.keys())} scammer addresses.")
    for scammer_address in scammer_addresses_dict.keys():
        scammer_address_lower = scammer_address.lower()
        scammer_contract_addresses = scammer_addresses_dict[scammer_address]['scammer-contracts'] if 'scammer-contracts' in scammer_addresses_dict[scammer_address] else set()
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got scammer address {scammer_address_lower}")
        cluster = scammer_address_lower
        entity_cluster = read_entity_clusters(scammer_address_lower)
        if scammer_address_lower in entity_cluster.keys():
            cluster = entity_cluster[scammer_address_lower]
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got alert for cluster {cluster}")

        if Utils.is_contract(w3, cluster):
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} is contract, skipping")
            continue

        alert_id_target = alert_target(alert_event, BASE_BOTS)
        alert_id = "SCAM-DETECTOR-ADDRESS-POISONER" if scammer_addresses_dict[scammer_address]["address_information"] == "poisoner" else alert_id_target
        if already_alerted(cluster, alert_id, "passthrough"):
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} already alerted on for {alert_id}; skipping")
            continue

        if Utils.is_fp(w3, cluster, CHAIN_ID):
            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} identified as FP; skipping")
            continue

        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
        created_at_datetime = datetime.strptime(alert_event.alert.created_at[0:19], "%Y-%m-%dT%H:%M:%S")
        metadata = scammer_addresses_dict[scammer_address]
        findings.append(ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, scammer_address_lower, created_at_datetime, created_at_datetime, scammer_contract_addresses, alert_event.alert.addresses, {alert_event.alert_id}, alert_id, {alert_event.alert_hash}, metadata, CHAIN_ID, "passthrough"))
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} added to findings. Findings size: {len(findings)}")
        update_list(ALERTED_ENTITIES_PASSTHROUGH, ALERTED_ENTITIES_PASSTHROUGH_QUEUE_SIZE, cluster, alert_id, "passthrough")

    scammer_urls_dict = BaseBotParser.get_scammer_urls(w3, alert_event)
    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got base bot alert (passthrough); extracted {len(scammer_urls_dict.keys())} scammer urls.")
    for scammer_url in scammer_urls_dict.keys():
        scammer_address = scammer_urls_dict[scammer_url]['scammer'] if 'scammer' in scammer_urls_dict[scammer_url] else scammer_urls_dict[scammer_url]['tokenDeployer'] if 'tokenDeployer' in scammer_urls_dict[scammer_url] else scammer_urls_dict[scammer_url]['scammer'] if 'scammer' in scammer_urls_dict[scammer_url] else ""
        if scammer_address == "": # this implies we are dealing with a url which doesnt have a scammer address and we emit a finding; if it does, it has already been handled above and we dont emit a finding
            alert_id_target = alert_target(alert_event, BASE_BOTS)
            alert_id = "SCAM-DETECTOR-ADDRESS-POISONER" if scammer_urls_dict[scammer_url]["address_information"] == "poisoner" else alert_id_target
            if already_alerted(scammer_url, alert_id, "passthrough"):
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - url {scammer_url} already alerted on for {alert_id}; skipping")
                continue

            if Utils.is_fp(w3, scammer_url, CHAIN_ID, False):
                logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - url {scammer_url} identified as FP; skipping")
                continue

            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - url {scammer_url} not in FP mitigation clusters")
            created_at_datetime = datetime.strptime(alert_event.alert.created_at[0:19], "%Y-%m-%dT%H:%M:%S")
            metadata = scammer_urls_dict[scammer_url]
            findings.append(ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, "", created_at_datetime, created_at_datetime, set(), alert_event.alert.addresses, {alert_event.alert_id}, alert_id, {alert_event.alert_hash}, metadata, -1, "passthrough"))
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - url {scammer_url} added to findings. Findings size: {len(findings)}")
            update_list(ALERTED_ENTITIES_PASSTHROUGH, ALERTED_ENTITIES_PASSTHROUGH_QUEUE_SIZE, scammer_url, alert_id, "passthrough")



    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - return total findings: {len(findings)}")
    return findings

def emit_contract_similarity_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global ALERTED_ENTITIES_SIMILAR_CONTRACT
    global ALERTED_ENTITIES_SIMILAR_CONTRACT_QUEUE_SIZE
    global CONTRACT_SIMILARITY_BOT_THRESHOLDS
    global CHAIN_ID

    findings = []
    scammer_addresses_lower = BaseBotParser.get_scammer_addresses(w3, alert_event)
    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got contract similarity bot alert; got {len(scammer_addresses_lower)} scammer addresses.")
    for scammer_address_lower in scammer_addresses_lower:
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - processing contract similarity bot address {scammer_address_lower}")

        similarity_score = float(alert_event.alert.metadata['similarity_score']) if 'similarity_score' in alert_event.alert.metadata else float(alert_event.alert.metadata['similarityScore'])
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - {scammer_address_lower} similarity score {similarity_score}")
        if similarity_score > CONTRACT_SIMILARITY_BOT_THRESHOLDS[0]:
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - similarity score {similarity_score} is above threshold {CONTRACT_SIMILARITY_BOT_THRESHOLDS[0]}")
            if not Utils.is_fp(w3, scammer_address_lower, CHAIN_ID):
                
                if not already_alerted(scammer_address_lower, "SCAM-DETECTOR-SIMILAR-CONTRACT", "similar_contract"):
                    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower}; emitting finding")
                    update_list(ALERTED_ENTITIES_SIMILAR_CONTRACT, ALERTED_ENTITIES_SIMILAR_CONTRACT_QUEUE_SIZE, scammer_address_lower, "SCAM-DETECTOR-SIMILAR-CONTRACT", "similar_contract")
                    finding = ScamDetectorFinding.alert_similar_contract(block_chain_indexer, forta_explorer, alert_event.alert.alert_id, alert_event.alert_hash, alert_event.alert.metadata, CHAIN_ID)
                    if(finding is not None):
                        findings.append(finding)
                    else:
                        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - finding is none due to original threat category not being in list flagged for propagation")
                else:
                    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower} already alerted")
            else:
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower} in FP.")
    return findings


def emit_eoa_association_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global ALERTED_ENTITIES_SCAMMER_ASSOCIATION
    global ALERTED_ENTITIES_SCAMMER_ASSOCIATION_QUEUE_SIZE
    global EOA_ASSOCIATION_BOT_THRESHOLDS
    global CHAIN_ID

    findings = []
    scammer_addresses_lower = BaseBotParser.get_scammer_addresses(w3, alert_event)
    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got eoa association bot alert; got {len(scammer_addresses_lower)} scammer addresses.")
    for scammer_address_lower in scammer_addresses_lower:
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - processing eoa association bot address {scammer_address_lower}")

        model_confidence = float(alert_event.alert.metadata['model_confidence']) if 'model_confidence' in alert_event.alert.metadata else float(alert_event.alert.metadata['modelConfidence'])
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - {scammer_address_lower} model confidence {model_confidence}")
        if model_confidence > EOA_ASSOCIATION_BOT_THRESHOLDS[0]:
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - model confidence {model_confidence} is above threshold {EOA_ASSOCIATION_BOT_THRESHOLDS[0]}")
            if not Utils.is_fp(w3, scammer_address_lower, CHAIN_ID):
                if not already_alerted(scammer_address_lower, "SCAM-DETECTOR-SCAMMER-ASSOCIATION", "scammer_association"):
                    update_list(ALERTED_ENTITIES_SCAMMER_ASSOCIATION, ALERTED_ENTITIES_SCAMMER_ASSOCIATION_QUEUE_SIZE, scammer_address_lower, "SCAM-DETECTOR-SCAMMER-ASSOCIATION", "scammer_association")
                    #"central_node":"0x13549e22de184a881fe3d164612ef15f99f6d4b3",
                    # "central_node_alert_hash":"0xbda39ad1c0a53555587a8bc9c9f711f0cad81fe89ef235a6d79ee905bc70526c",
                    # "central_node_alert_id":"SCAM-DETECTOR-ICE-PHISHING",
                     
                    existing_scammer_eoa = alert_event.alert.metadata['central_node'] if 'central_node' in alert_event.alert.metadata else alert_event.alert.metadata['centralNode']
                    original_alert_hash = alert_event.alert.metadata['central_node_alert_hash'] if 'central_node_alert_hash' in alert_event.alert.metadata else alert_event.alert.metadata['centralNodeAlertHash']
                    original_alert_id = alert_event.alert.metadata['central_node_alert_id'] if 'central_node_alert_id' in alert_event.alert.metadata else alert_event.alert.metadata['centralNodeAlertId']

                    finding = ScamDetectorFinding.scammer_association(block_chain_indexer, forta_explorer, scammer_address_lower, model_confidence, alert_event.alert.alert_id, alert_event.alert_hash, existing_scammer_eoa, original_alert_id, original_alert_hash, CHAIN_ID)
                    if(finding is not None):
                        findings.append(finding)
                else:
                    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower} already alerted")
            else:
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower} in FP.")
    return findings


def emit_metamask_finding(w3, test = False) -> list:
    global ALERTED_ENTITIES_MANUAL_METAMASK
    global ALERTED_ENTITIES_MANUAL_METAMASK_QUEUE_SIZE
    global CHAIN_ID
    global INITIAL_METAMASK_LIST_CONSUMPTION
    findings = []

    if CHAIN_ID == -1:
        logging.error("Chain ID not set")
        raise Exception("Chain ID not set")
    
    global ENABLE_METAMASK_CONSUMPTION
    if ENABLE_METAMASK_CONSUMPTION and CHAIN_ID == 1: #given the metamask list doesnt have chain info, we will only emit from nodes that are associated with mainnet
        try: 
            alert_id = "SCAM-DETECTOR-MANUAL-METAMASK-PHISHING"

            if INITIAL_METAMASK_LIST_CONSUMPTION:
                for alert_ids_for_entity in ALERTED_ENTITIES_MANUAL_METAMASK.values():
                    if any(logic_plus_alert_id.endswith(alert_id) for logic_plus_alert_id in alert_ids_for_entity):
                        INITIAL_METAMASK_LIST_CONSUMPTION = False
                        break

            metamask_phishing_urls = Utils.get_metamask_phishing_list()
            for url in metamask_phishing_urls:
                url = url[:-1] if url.endswith(",") else url # remove trailing comma from URLs that have it
                
                if not already_alerted(url, alert_id, "manual_metamask"):
                    logging.info(f"Manual finding: Emitting metamask finding for {url}")
                    update_list(ALERTED_ENTITIES_MANUAL_METAMASK, ALERTED_ENTITIES_MANUAL_METAMASK_QUEUE_SIZE, url, alert_id, "manual_metamask")
                    finding = ScamDetectorFinding.scam_finding_manual(block_chain_indexer, forta_explorer, "Url", url, "Metamask phishing", "Metamask (https://github.com/MetaMask/eth-phishing-detect/)", "", "", INITIAL_METAMASK_LIST_CONSUMPTION)
                    if finding is not None:
                        findings.append(finding)
                    logging.info(f"Findings count {len(findings)}")
                else:
                    logging.info(f"Metamask finding: Already alerted on {url}")

        except Exception as e:
            logging.warning(f"Manual finding: Failed to process metamask finding: {e} : {traceback.format_exc()}")
            Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.emit_metamask_finding", traceback.format_exc()))

    return findings


def emit_manual_finding(w3, test = False) -> list:
    global ALERTED_ENTITIES_MANUAL
    global ALERTED_ENTITIES_MANUAL_QUEUE_SIZE
    global CHAIN_ID
    findings = []

    if CHAIN_ID == -1:
        logging.error("Chain ID not set")
        raise Exception("Chain ID not set")
    
    try:
        df_manual_findings = Utils.get_manual_list()
        for index, row in df_manual_findings.iterrows():
            chain_id = -1
            try:
                chain_id_float = row['Chain ID']
                if math.isnan(chain_id_float):
                    logging.info("Manual finding: No chainID; setting to 1 as default.")
                    chain_id = 1
                else:
                    chain_id = int(chain_id_float)
            except Exception as e:
                logging.warning("Manual finding: Failed to get chain ID from manual finding")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.emit_manual_finding", traceback.format_exc()))
                continue

            if chain_id != CHAIN_ID:
                logging.info("Manual finding: Manual entry doesnt match chain ID.")
                continue

            try:
                entity_type = row['EntityType']
                if entity_type == "Address":
                    scammer_address_lower = row['Entity'].lower().strip()
                    cluster = scammer_address_lower
                    logging.info(f"Manual finding: Have manual entry for {scammer_address_lower}")
                    entity_clusters = read_entity_clusters(scammer_address_lower)
                    if scammer_address_lower in entity_clusters.keys():
                        cluster = entity_clusters[scammer_address_lower]

                    if Utils.is_contract(w3, cluster):
                        logging.info(f"Manual finding: Address {cluster} is a contract. Not alerting.")
                        continue

                    threat_category = "unknown" if 'nan' in str(row["Threat category"]) else row['Threat category']
                    alert_id_threat_category = threat_category.upper().replace(" ", "-")
                    alert_id = "SCAM-DETECTOR-MANUAL-"+alert_id_threat_category
                    if not already_alerted(cluster, alert_id, "manual"):
                        logging.info(f"Manual finding: Emitting manual finding for {cluster}")
                        tweet = "" if 'nan' in str(row["Tweet"]) else row['Tweet']
                        account = "" if 'nan' in str(row["Account"]) else row['Account']
                        comment = "" if 'nan' in str(row["Comment"]) else row['Comment']
                        attribution = "" if 'nan' in str(row["Attribution"]) else row['Attribution']
                        update_list(ALERTED_ENTITIES_MANUAL, ALERTED_ENTITIES_MANUAL_QUEUE_SIZE, cluster, alert_id, "manual")
                        finding = ScamDetectorFinding.scam_finding_manual(block_chain_indexer, forta_explorer, entity_type, cluster, threat_category, account + " " + tweet, chain_id, comment, False, attribution)
                        if finding is not None:
                            findings.append(finding)
                        logging.info(f"Findings count {len(findings)}")

                    else:
                        logging.info(f"Manual finding: Already alerted on {scammer_address_lower}")

                if entity_type == "Url":
                    url_lower = row['Entity'].lower().strip()
                    threat_category = "unknown" if 'nan' in str(row["Threat category"]) else row['Threat category']
                    alert_id_threat_category = threat_category.upper().replace(" ", "-")
                    alert_id = "SCAM-DETECTOR-MANUAL-"+alert_id_threat_category
                    if not already_alerted(url_lower, alert_id, "manual"):
                        logging.info(f"Manual finding: Emitting manual finding for {url_lower}")
                        tweet = "" if 'nan' in str(row["Tweet"]) else row['Tweet']
                        account = "" if 'nan' in str(row["Account"]) else row['Account']
                        comment = "" if 'nan' in str(row["Comment"]) else row['Comment']
                        attribution = "" if 'nan' in str(row["Attribution"]) else row['Attribution']
                        update_list(ALERTED_ENTITIES_MANUAL, ALERTED_ENTITIES_MANUAL_QUEUE_SIZE, url_lower, alert_id, "manual")
                        finding = ScamDetectorFinding.scam_finding_manual(block_chain_indexer, forta_explorer, entity_type, url_lower, threat_category, account + " " + tweet, chain_id, comment, False, attribution)
                        if finding is not None:
                            findings.append(finding)
                        logging.info(f"Findings count {len(findings)}")
                    else:
                        logging.info(f"Manual finding: Already alerted on {url_lower}")

            except Exception as e:
                logging.warning(f"Manual finding: Failed to process manual finding: {e} : {traceback.format_exc()}")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.emit_manual_finding.internal", traceback.format_exc()))
                continue
    
    except Exception as e:
        logging.warning(f"Manual finding: Failed to process manual finding: {e} : {traceback.format_exc()}")
        Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.emit_manual_finding", traceback.format_exc()))

    

    return findings

# clear cache flag for perf testing
def detect_scam(w3, alert_event: forta_agent.alert_event.AlertEvent, clear_state_flag = False) -> list:
    
    if clear_state_flag:
        clear_state()

    global ENTITY_CLUSTER_BOTS
    global CHAIN_ID
    global BASE_BOTS
    global secrets

    
    findings = []
    try:
        start_all = time.time()

        if CHAIN_ID == -1:
            reinitialize()
            if CHAIN_ID == -1:
                logging.error(f"{BOT_VERSION}: CHAIN_ID not set")
                raise Exception("CHAIN_ID not set")

        chain_id = int(alert_event.chain_id) 
        if chain_id == CHAIN_ID:
            # got alert from the right chain
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - received alert for proper chain {CHAIN_ID}")

            # decrypt the alert if needed
            if alert_event.bot_id in ENCRYPTED_BOTS.keys() and alert_event.name == 'omitted':
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - decrypting alert event.") 
                decryption_key_name = ENCRYPTED_BOTS[alert_event.bot_id]
                if decryption_key_name in secrets['decryptionKeys']:
                    private_key = secrets['decryptionKeys'][decryption_key_name]
                    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - decrypting alert. Private key length for {decryption_key_name}: {len(private_key)}")
                    alert_event = Utils.decrypt_alert_event(alert_event, private_key)

            # update entity clusters
            if in_list(alert_event, ENTITY_CLUSTER_BOTS):
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} is entity cluster alert")
                cluster = alert_event.alert.metadata["entityAddresses"].lower()

                for address in cluster.split(','):
                    put_entity_cluster(alert_event.alert.created_at, address, cluster)

            # for basebots, three paths:
            # for contract similarity, a bit more work
            # for passthroughs, simply emit an alert (pot with some adjustments on mappings)
            # for combination base bots store in dynamo; then query dynamo for the cluster (this will pull all alerts from multiple shards), build feature vector and then evaluate detection heuristic
            
            if in_list(alert_event, CONTRACT_SIMILARITY_BOTS):
                start = time.time()
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} is contract similarity alert")
                findings.extend(emit_contract_similarity_finding(w3, alert_event))
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} is contract similarity alert. Processing took {time.time() - start} seconds.")
            elif in_list(alert_event, EOA_ASSOCIATION_BOTS):
                start = time.time()
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} is eoa association alert")
                findings.extend(emit_eoa_association_finding(w3, alert_event))
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} is eoa association alert. Processing took {time.time() - start} seconds.")
            elif alert_logic(alert_event, BASE_BOTS) == "PassThrough":
                start = time.time()
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - is passthrough alert")
                findings = []
                # if Utils.is_beta():
                #     findings.extend(emit_ml_finding(w3, alert_event)) # pushing passthrough to assess how well we would do with an ML approach; this is more for testing purposes right now
                findings.extend(emit_passthrough_finding(w3, alert_event))
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - is passthrough alert. Processing took {time.time() - start} seconds.")
                
            elif alert_logic(alert_event, BASE_BOTS) == "Combination":  
                start = time.time()
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - is combination alert")
                findings.extend(emit_ml_finding(w3, alert_event))
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - is combination alert. Processing took {time.time() - start} seconds.")
            else:
                logging.warning(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got base bot alert; not part of subscription")
        else:
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - wrong chain {chain_id} for bot {CHAIN_ID}")

        end_all = time.time()
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.alert_id} {alert_event.chain_id} processing took {end_all - start_all} seconds")
    except BaseException as e:
        logging.warning(f"{BOT_VERSION}: alert {alert_event.alert_hash} - Exception in process_alert {alert_event.alert_hash}: {e} - {traceback.format_exc()}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV') and not Utils.is_beta() and not Utils.is_beta_alt():
            logging.error(f"{BOT_VERSION}: alert {alert_event.alert_hash} - Raising exception to expose error to scannode")
            raise e
        else:
            Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.detect_scam", traceback.format_exc()))
   
    return findings

# This function emits FPs for each address in the static list maintained by the Forta Community residing on github
# FPs are processed by emitting a label with the remove flag set to True; note, the label needs to match the original label, so we need to pull the original label from the API
# Further, given a label - through propagation - could expand out, the algorithm needs to assess what labels were set due to propagation and remove those as well
def emit_new_fp_finding(w3) -> list:
    global ALERTED_FP_CLUSTERS
    global CHAIN_ID
    global ALERTED_FP_CLUSTERS_QUEUE_SIZE

    if CHAIN_ID == -1:
        reinitialize()
        if CHAIN_ID == -1:
            logging.error(f"{BOT_VERSION}: CHAIN_ID not set")
            raise Exception("CHAIN_ID not set")
    findings = []

    similar_contract_labels = None
    scammer_association_labels = None

    try:
        df_fp = Utils.get_fp_list()
        for index, row in df_fp.iterrows():
            try:
                chain_id = int(str(row['chain_id']).strip())
                if chain_id != CHAIN_ID:
                    continue
                cluster = row['address'].lower().strip()
                if cluster not in ALERTED_FP_CLUSTERS.keys():
                    update_list(ALERTED_FP_CLUSTERS, ALERTED_FP_CLUSTERS_QUEUE_SIZE, cluster, "SCAM-DETECTOR-FALSE-POSITIVE")
                    for address in cluster.split(','):
                        if scammer_association_labels is None:
                            scammer_association_labels = get_scammer_association_labels(w3, forta_explorer)
                        if similar_contract_labels is None:
                            similar_contract_labels = get_similar_contract_labels(w3, forta_explorer)
                        
                        for (entity, label, metadata, unique_key) in obtain_all_fp_labels(w3, address, block_chain_indexer, forta_explorer, similar_contract_labels, scammer_association_labels, CHAIN_ID):
                            logging.info(f"{BOT_VERSION}: Emitting FP mitigation finding for {entity} {label}")
                            update_list(ALERTED_FP_CLUSTERS, ALERTED_FP_CLUSTERS_QUEUE_SIZE, entity, "SCAM-DETECTOR-FALSE-POSITIVE")
                            findings.append(ScamDetectorFinding.alert_FP(w3, entity, label, metadata, [unique_key]))
                            logging.info(f"{BOT_VERSION}: Findings count {len(findings)}")
            except Exception as e:
                logging.warning(f"{BOT_VERSION}: emit fp finding exception: {e} - {traceback.format_exc()}")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.emit_new_fp_finding.internal", traceback.format_exc()))
    except Exception as e:
        logging.warning(f"{BOT_VERSION}: emit fp finding exception: {e} - {traceback.format_exc()}")
        Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.emit_new_fp_finding", traceback.format_exc()))

    return findings


# This function is called once per hour to update the REACTIVE_LIKELY_FPS dictionary. 
# It fetches scammer addresses from Scam Detector alerts generated 89 days ago (at that specific hour) and then retrieves 
# scammer labels for those addresses. The retrieved data is used to update the dictionary.
def update_reactive_likely_fps(w3, current_date) -> list:
    logging.info(f"{BOT_VERSION}: update reactive likely fps called")
    global REACTIVE_LIKELY_FPS
    global ALERTED_FP_CLUSTERS
    global SIMILAR_CONTRACT_LABELS
    global SCAMMER_ASSOCIATION_LABELS
    global LAST_PROCESSED_TIME
    findings = []

    current_time = int(current_date.timestamp())

    if current_date.minute == 0 and current_time - LAST_PROCESSED_TIME > 3500:
        logging.info(f"{BOT_VERSION}: update reactive likely fps called on the 00 minute. Querying past labels.")
        LAST_PROCESSED_TIME = current_time

        source_id = SCAM_DETECTOR_BETA_ALT_BOT_ID if Utils.is_beta_alt() else (SCAM_DETECTOR_BETA_BOT_ID if Utils.is_beta() else SCAM_DETECTOR_BOT_ID)
        
        # Calculate timestamps for different periods (7 days, 30 days)
        periods = {
            "7_days_ago": current_date - timedelta(days=7),
            "30_days_ago": current_date - timedelta(days=30),
        }
        start = time.time()

        for period_name, period_date in periods.items():
            # fetch_alerts 
            milliseconds_ago = (current_date - period_date).total_seconds() * 1000
            start_milliseconds_ago = int(milliseconds_ago)
            end_milliseconds_ago = int(milliseconds_ago - 3600 * 1000)

            # fetch_labels
            current_unix_timestamp_ms = int(current_date.timestamp() * 1000)
            period_in_days = (current_date - period_date).days
            period_in_ms = period_in_days * 24 * 60 * 60 * 1000
            get_labels_created_since_timestamp_ms = current_unix_timestamp_ms - period_in_ms

            alerts = Utils.fetch_alerts(source_id, start_milliseconds_ago, end_milliseconds_ago, BOT_VERSION, CHAIN_ID)
            logging.info(f"{BOT_VERSION}: update reactive likely fps (alerts count {period_name}): {len(alerts)}")

            unique_scammers_list = Utils.process_past_alerts(alerts, REACTIVE_LIKELY_FPS, BOT_VERSION)

            labels = Utils.fetch_labels(unique_scammers_list, source_id, get_labels_created_since_timestamp_ms, BOT_VERSION)
            logging.info(f"{BOT_VERSION}: update reactive likely fps (labels count {period_name}): {len(labels)}")

            for label in labels:
                if not label.remove:
                    # There may be multiple labels for the same scammer entity, due to different label metadata
                    entity, metadata, unique_key = label.entity, label.metadata, label.unique_key
                    if entity not in REACTIVE_LIKELY_FPS:
                       REACTIVE_LIKELY_FPS[entity] = ([metadata], [unique_key])
                    else:
                        REACTIVE_LIKELY_FPS[entity][0].append(metadata)  # Append to the metadata list
                        REACTIVE_LIKELY_FPS[entity][1].append(unique_key)  # Append to the unique key list
        end = time.time()
        logging.info(f"{BOT_VERSION}: update reactive likely fps (REACTIVE_LIKELY_FPS count): {len(REACTIVE_LIKELY_FPS)}")
        logging.info(f"{BOT_VERSION}: update reactive likely fps (processing took): {end - start} seconds")
    else:
        #  Create reactive FP findings
        if REACTIVE_LIKELY_FPS:
            if current_date.minute == 5:
                # Refresh the data every hour (at the 05 minute)
                SIMILAR_CONTRACT_LABELS = None
                SCAMMER_ASSOCIATION_LABELS = None

            address = next(iter(REACTIVE_LIKELY_FPS), None)
            logging.info(f"{BOT_VERSION}: Processing address: {address}")
            if Utils.is_fp(w3, address, CHAIN_ID):
                logging.info(f"{BOT_VERSION}: {address} is an FP. Emitting FP finding.")
                update_list(ALERTED_FP_CLUSTERS, ALERTED_FP_CLUSTERS_QUEUE_SIZE, address, "SCAM-DETECTOR-FALSE-POSITIVE")
                metadata_array, unique_keys_array = REACTIVE_LIKELY_FPS[address]
                findings.append(ScamDetectorFinding.alert_FP(w3, address, "scammer", metadata_array, unique_keys_array))
                if SCAMMER_ASSOCIATION_LABELS is None:
                        SCAMMER_ASSOCIATION_LABELS = get_scammer_association_labels(w3, forta_explorer)
                if SIMILAR_CONTRACT_LABELS is None:
                    SIMILAR_CONTRACT_LABELS = get_similar_contract_labels(w3, forta_explorer)
                for (entity, label, metadata, unique_key) in obtain_all_fp_labels(w3, address, block_chain_indexer, forta_explorer, SIMILAR_CONTRACT_LABELS, SCAMMER_ASSOCIATION_LABELS, CHAIN_ID):
                        logging.info(f"{BOT_VERSION}: Processing entity: {entity} - {label}")
                        if entity != address:
                            logging.info(f"{BOT_VERSION}: Emitting FP mitigation finding for {entity} {label}")
                            update_list(ALERTED_FP_CLUSTERS, ALERTED_FP_CLUSTERS_QUEUE_SIZE, entity, "SCAM-DETECTOR-FALSE-POSITIVE")
                            findings.append(ScamDetectorFinding.alert_FP(w3, entity, label, metadata, [unique_key]))
                            if entity in REACTIVE_LIKELY_FPS:
                                del REACTIVE_LIKELY_FPS[entity]                            
            
            del REACTIVE_LIKELY_FPS[address]
            logging.info(f"{BOT_VERSION}: {len(REACTIVE_LIKELY_FPS)} likely FPs yet to be processed")
   
    return findings

def get_value(items: dict, key: str):
    v = ''
    if key in items:
        v = items[key].lower()

    return v

# contains from_entity, from_entity_deployer, to_entity, to_entity_deployer
def get_similar_contract_labels(w3, forta_explorer) -> pd.DataFrame:
    source_id = SCAM_DETECTOR_BETA_ALT_BOT_ID if Utils.is_beta_alt() else (SCAM_DETECTOR_BETA_BOT_ID if Utils.is_beta() else SCAM_DETECTOR_BOT_ID)
    df_labels = forta_explorer.get_labels(source_id, datetime(2023,3,1), datetime.now(), label_query = "similar-contract")
    df_labels.rename(columns={'entity': 'to_entity'}, inplace=True)
    df_labels['from_entity'] = df_labels['metadata'].apply(lambda x: get_value(x, "associated_scammer_contract"))
    df_labels['deployer_info'] = df_labels['metadata'].apply(lambda x: get_value(x, "deployer_info"))
    df_labels['from_entity_deployer'] = df_labels['deployer_info'].apply(lambda x: x[216:216+42])
    df_labels['to_entity_deployer'] = df_labels['deployer_info'].apply(lambda x: x[9:9+42])
    # drop all but from_entity and to_entity
    df_labels.drop(df_labels.columns.difference(['from_entity', 'from_entity_deployer', 'to_entity', 'to_entity_deployer']), axis=1, inplace=True)                                      
    return df_labels



# contains from_entity and to_entity
def get_scammer_association_labels(w3, forta_explorer) -> pd.DataFrame:
    source_id = SCAM_DETECTOR_BETA_ALT_BOT_ID if Utils.is_beta_alt() else (SCAM_DETECTOR_BETA_BOT_ID if Utils.is_beta() else SCAM_DETECTOR_BOT_ID)
    df_labels = forta_explorer.get_labels(source_id, datetime(2023,3,1), datetime.now(), label_query = "scammer-association")
    df_labels.rename(columns={'entity': 'to_entity'}, inplace=True)
    # lower case all addresses
    df_labels['to_entity'] = df_labels['to_entity'].apply(lambda x: x.lower())
    df_labels['from_entity'] = df_labels['metadata'].apply(lambda x: get_value(x, "associated_scammer"))
    # drop all but from_entity and to_entity
    df_labels.drop(df_labels.columns.difference(['from_entity', 'to_entity']), axis=1, inplace=True)                                      
    return df_labels



# this function returns a list of all labels that need to be removed with the address as a starting point
# it contain a queue of addresses to process and a set of addresses that have already been processed
# returns a tuple of (entity, threat_category, metadata); metadata is a tuple of key=value pairs because its not hashable otherwise
def obtain_all_fp_labels(w3, starting_address: str, block_chain_indexer, forta_explorer, similar_contract_labels: pd.DataFrame, scammer_association_labels: pd.DataFrame, chain_id: int) -> set:
    global ALERTED_FP_CLUSTERS
    global ALERTED_FP_CLUSTERS_QUEUE_SIZE

    logging.info(f"{BOT_VERSION}: {starting_address} obtain_all_fp_labels")

    source_id = SCAM_DETECTOR_BETA_ALT_BOT_ID if Utils.is_beta_alt() else (SCAM_DETECTOR_BETA_BOT_ID if Utils.is_beta() else SCAM_DETECTOR_BOT_ID)

    fp_labels = set()

    to_process = set()
    processed = set()
    to_process.add(starting_address)
    while len(to_process) > 0:
        address = to_process.pop().lower()
        if address in processed:
            continue

        if Utils.is_contract(w3, address):
            forta_labels = forta_explorer.get_labels(source_id, datetime(2023,1,1), datetime.now(), entity=address)
            logging.info(f"{BOT_VERSION}: {starting_address} processing contract {address}. Obtained {len(forta_labels)} labels")
            for index, row in forta_labels.iterrows():
                logging.info(f"{BOT_VERSION}: {starting_address} processing contract {address}. Label {row['labelstr']}")
                if row['metadata'] is not None and "address_type" in row['metadata'].keys() and "threat_category" in row['metadata'].keys() and row['metadata']['address_type'] == 'contract':
                    threat_category = row['metadata']['threat_category']
                    label = row['labelstr']
                    unique_key = row['uniqueKey']
                    logging.info(f"{BOT_VERSION}: {starting_address} adding FP label threat category {threat_category} for contract {address}")
                    fp_labels.add((address,label, tuple([f"{k}={v}" for k, v in row['metadata'].items()]), unique_key))

                    similar_contract_labels_for_address = similar_contract_labels[similar_contract_labels['from_entity'] == address]
                    for index, row in similar_contract_labels_for_address.iterrows():
                        logging.info(f"{BOT_VERSION}: {starting_address} adding to process due to contract similarity from_entity {address} -> to_entity {row['to_entity']}, to_entity_deployer {row['to_entity_deployer']}, from_entity_deployer {row['from_entity_deployer']}")
                        to_process.add(row['to_entity'])
                        to_process.add(row['to_entity_deployer'])
                        to_process.add(row['from_entity_deployer'])

                    similar_contract_labels_for_address = similar_contract_labels[similar_contract_labels['to_entity'] == address]
                    for index, row in similar_contract_labels_for_address.iterrows():
                        logging.info(f"{BOT_VERSION}: {starting_address} adding to process due to contract similarity to_entity {address} -> from_entity {row['from_entity']}, from_entity_deployer {row['from_entity_deployer']}, to_entity_deployer {row['to_entity_deployer']}")
                        to_process.add(row['from_entity'])
                        to_process.add(row['from_entity_deployer'])
                        to_process.add(row['to_entity_deployer'])


        else:
            forta_labels = forta_explorer.get_labels(source_id, datetime(2023,1,1), datetime.now(), entity=address)
            logging.info(f"{BOT_VERSION}: {starting_address} processing EOA {address}. Obtained {len(forta_labels)} labels")
            for index, row in forta_labels.iterrows():
                logging.info(f"{BOT_VERSION}: {starting_address} processing EOA {address}. Label {row['labelstr']}")
                if row['metadata'] is not None and "address_type" in row['metadata'].keys() and "threat_category" in row['metadata'].keys() and row['metadata']['address_type'] == 'EOA':
                    threat_category = row['metadata']['threat_category']
                    label = row['labelstr']
                    unique_key = row['uniqueKey']
                    logging.info(f"{BOT_VERSION}: {starting_address} adding FP label threat category {threat_category} for EOA {address}")
                    fp_labels.add((address,label,tuple([f"{k}={v}" for k, v in row['metadata'].items()]), unique_key))

                    # query all deployed contract and add to to_process set
                    contract_addresses = block_chain_indexer.get_contracts(address, chain_id)
                    if len(contract_addresses) > 0:
                        logging.info(f"{BOT_VERSION}: {starting_address} adding to process from deployer {address} -> contract addresses {','.join(contract_addresses)}")
                        to_process.update(contract_addresses)
                    else:
                        logging.info(f"{BOT_VERSION}: {starting_address} no contracts found for deployer {address}")

                    # assess whether there are any scammer association propagation labels for this address and add to to_process set
                    scammer_association_labels_for_address = scammer_association_labels[scammer_association_labels['from_entity'] == address]
                    for index, row in scammer_association_labels_for_address.iterrows():
                        logging.info(f"{BOT_VERSION}: {starting_address} adding to process from from_entity {address} -> to_entity {row['to_entity']}")
                        to_process.add(row['to_entity'])

                    scammer_association_labels_for_address = scammer_association_labels[scammer_association_labels['to_entity'] == address]
                    for index, row in scammer_association_labels_for_address.iterrows():
                        logging.info(f"{BOT_VERSION}: {starting_address} adding to process from to_entity {address} -> to_entity {row['from_entity']}")
                        to_process.add(row['from_entity'])
                        

        processed.add(address)
        update_list(ALERTED_FP_CLUSTERS, ALERTED_FP_CLUSTERS_QUEUE_SIZE, address, "SCAM-DETECTOR-FALSE-POSITIVE")

    return fp_labels





def get_original_threat_category_alert_hash(address: str) -> (tuple):

    source_id = SCAM_DETECTOR_BETA_ALT_BOT_ID if Utils.is_beta_alt() else (SCAM_DETECTOR_BETA_BOT_ID if Utils.is_beta() else SCAM_DETECTOR_BOT_ID)
    labels_df = FortaExplorer.get_labels(source_id, datetime(2023,1,1), datetime.now(), entity = address.lower())
    for index, row in labels_df.iterrows():
        if row['metadata'] is not None and "address_type" in row['metadata'].keys() and "threat_category" in row['metadata'].keys() and row['metadata']['address_type'] == 'EOA':
            threat_category = row['metadata']['threat_category']
            return (threat_category, row["alertHash"])

    return ("", "")


def detect_scammer_contract_creation(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global DF_CONTRACT_SIGNATURES
    global ALERTED_ENTITIES_MANUAL
    global ALERTED_ENTITIES_MANUAL_QUEUE_SIZE
    findings = []

    try:
        if transaction_event.to is None:
            nonce = transaction_event.transaction.nonce
            created_contract_address = Utils.calc_contract_address(w3, transaction_event.from_, nonce)
            logging.info(f"{BOT_VERSION}: {transaction_event.from_} created contract {created_contract_address}")
            original_threat_category, original_alert_hash = get_original_threat_category_alert_hash(transaction_event.from_)
            if original_threat_category != "":
                findings.append(ScamDetectorFinding.scammer_contract_deployment(transaction_event.from_, created_contract_address.lower(), original_threat_category, original_alert_hash, CHAIN_ID))

            code = Utils.get_code(w3, created_contract_address)
            for index, row in DF_CONTRACT_SIGNATURES.iterrows():
                code_regex = row["Entity"]
                if re.search(code_regex, code):
                    logging.info(row['Threat category'])
                    logging.info(f"{BOT_VERSION}: {transaction_event.from_} created contract {created_contract_address} matches {code_regex}")
                    threat_category = "unknown" if 'nan' in str(row["Threat category"]) else row['Threat category']
                    alert_id_threat_category = threat_category.upper().replace(" ", "-")
                    alert_id = "SCAM-DETECTOR-MANUAL-"+alert_id_threat_category
                    if not already_alerted(transaction_event.from_, alert_id, "manual"):
                        tweet = "" if 'nan' in str(row["Tweet"]) else row['Tweet']
                        account = "" if 'nan' in str(row["Account"]) else row['Account']
                        comment = "" if 'nan' in str(row["Comment"]) else row['Comment']
                        attribution = "" if 'nan' in str(row["Attribution"]) else row['Attribution']
                        update_list(ALERTED_ENTITIES_MANUAL, ALERTED_ENTITIES_MANUAL_QUEUE_SIZE, transaction_event.from_, alert_id, "manual")
                        finding = ScamDetectorFinding.scam_finding_manual(block_chain_indexer, forta_explorer, "Address", transaction_event.from_, threat_category, account + " " + tweet, CHAIN_ID, comment, False, attribution)
                        if finding is not None:
                            logging.info(f"Manual finding: Emitting manual finding for {transaction_event.from_}")
                            findings.append(finding)
                    break

            
        pair_created_events = transaction_event.filter_log(PAIRCREATED_EVENT_ABI, SWAP_FACTORY_ADDRESSES[CHAIN_ID].lower())
        for event in pair_created_events:
            original_threat_category, original_alert_hash = get_original_threat_category_alert_hash(transaction_event.from_)
            if original_threat_category != "":
                created_contract_address = event['args']['pair']
                findings.append(ScamDetectorFinding.scammer_contract_deployment(transaction_event.from_, created_contract_address.lower(), original_threat_category, original_alert_hash, CHAIN_ID))

        pool_created_events = transaction_event.filter_log(POOLCREATED_EVENT_ABI, SWAP_FACTORY_ADDRESSES[CHAIN_ID].lower())
        for event in pool_created_events:
            original_threat_category, original_alert_hash = get_original_threat_category_alert_hash(transaction_event.from_)
            if original_threat_category != "":
                created_contract_address = event['args']['pool']
                findings.append(ScamDetectorFinding.scammer_contract_deployment(transaction_event.from_, created_contract_address.lower(), original_threat_category, original_alert_hash, CHAIN_ID))
    except BaseException as e:
        logging.warning(f"{BOT_VERSION}: transaction {transaction_event.hash} - Exception in detect_scammer_contract_creation {transaction_event.hash}: {e} - {traceback.format_exc()}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV') and not Utils.is_beta() and not Utils.is_beta_alt():
            logging.error(f"{BOT_VERSION}: transaction {transaction_event.hash} - Raising exception to expose error to scannode")
            raise e
        else:
            Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.detect_scammer_contract_creation", traceback.format_exc()))
    

    return findings


def clear_state():
    # delete cache file
    L2Cache.remove(CHAIN_ID, ALERTED_ENTITIES_ML_KEY)
    L2Cache.remove(CHAIN_ID, ALERTED_ENTITIES_PASSTHROUGH_KEY)
    L2Cache.remove(CHAIN_ID, ALERTED_ENTITIES_SCAMMER_ASSOCIATION_KEY)
    L2Cache.remove(CHAIN_ID, ALERTED_ENTITIES_SIMILAR_CONTRACT_KEY)
    L2Cache.remove(CHAIN_ID, ALERTED_ENTITIES_MANUAL_KEY)
    L2Cache.remove(CHAIN_ID, ALERTED_ENTITIES_MANUAL_METAMASK_KEY)
    L2Cache.remove(CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
    L2Cache.remove(CHAIN_ID, FINDINGS_CACHE_BLOCK_KEY)
    L2Cache.remove(CHAIN_ID, FINDINGS_CACHE_ALERT_KEY)
    L2Cache.remove(CHAIN_ID, FINDINGS_CACHE_TRANSACTION_KEY)
    
    Utils.FP_MITIGATION_ADDRESSES = set()
    Utils.CONTRACT_CACHE = dict()

def persist_state():    
    global ALERTED_ENTITIES_ML
    global ALERTED_ENTITIES_ML_KEY

    global ALERTED_ENTITIES_PASSTHROUGH
    global ALERTED_ENTITIES_PASSTHROUGH_KEY

    global ALERTED_ENTITIES_SCAMMER_ASSOCIATION
    global ALERTED_ENTITIES_SCAMMER_ASSOCIATION_KEY

    global ALERTED_ENTITIES_SIMILAR_CONTRACT
    global ALERTED_ENTITIES_SIMILAR_CONTRACT_KEY

    global ALERTED_ENTITIES_MANUAL
    global ALERTED_ENTITIES_MANUAL_KEY

    global ALERTED_ENTITIES_MANUAL_METAMASK
    global ALERTED_ENTITIES_MANUAL_METAMASK_LIST
    global ALERTED_ENTITIES_MANUAL_METAMASK_KEY

    global ALERTED_FP_CLUSTERS
    global ALERTED_FP_CLUSTERS_KEY

    global FINDINGS_CACHE_BLOCK
    global FINDINGS_CACHE_BLOCK_KEY

    global FINDINGS_CACHE_ALERT
    global FINDINGS_CACHE_ALERT_KEY

    global FINDINGS_CACHE_TRANSACTION
    global FINDINGS_CACHE_TRANSACTION_KEY

    global CHAIN_ID

    start = time.time()
    persist(ALERTED_ENTITIES_ML, CHAIN_ID, ALERTED_ENTITIES_ML_KEY)
    persist(ALERTED_ENTITIES_PASSTHROUGH, CHAIN_ID, ALERTED_ENTITIES_PASSTHROUGH_KEY)
    persist(ALERTED_ENTITIES_SCAMMER_ASSOCIATION, CHAIN_ID, ALERTED_ENTITIES_SCAMMER_ASSOCIATION_KEY)
    persist(ALERTED_ENTITIES_SIMILAR_CONTRACT, CHAIN_ID, ALERTED_ENTITIES_SIMILAR_CONTRACT_KEY)
    persist(ALERTED_ENTITIES_MANUAL, CHAIN_ID, ALERTED_ENTITIES_MANUAL_KEY)
    persist(ALERTED_FP_CLUSTERS, CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
    persist(FINDINGS_CACHE_BLOCK, CHAIN_ID, FINDINGS_CACHE_BLOCK_KEY)
    persist(FINDINGS_CACHE_ALERT, CHAIN_ID, FINDINGS_CACHE_ALERT_KEY)
    persist(FINDINGS_CACHE_TRANSACTION, CHAIN_ID, FINDINGS_CACHE_TRANSACTION_KEY)

    if CHAIN_ID == 1 and len(ALERTED_ENTITIES_MANUAL_METAMASK.keys()) > 0:
        ALERTED_ENTITIES_MANUAL_METAMASK_LIST = list(ALERTED_ENTITIES_MANUAL_METAMASK.keys())
        persist(ALERTED_ENTITIES_MANUAL_METAMASK_LIST, CHAIN_ID, ALERTED_ENTITIES_MANUAL_METAMASK_KEY)

    end = time.time()
    logging.info(f"Persisted bot state. took {end - start} seconds")


def persist(obj: object, chain_id: int, key: str):
    L2Cache.write(obj, chain_id, key)


def load(chain_id: int, key: str) -> object:
    return L2Cache.load(chain_id, key)


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

def provide_handle_alert(w3):
    logging.debug("provide_handle_alert called")
   
    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        logging.debug("handle_alert inner called")
        global INITIALIZED
        global INITIALIZED_CALLED
        global INITIALIZATION_TIME
        if not INITIALIZED:
            time_elapsed = datetime.now() - INITIALIZATION_TIME
            if (time_elapsed > timedelta(minutes=5)):
                logging.error(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle alert {INITIALIZED}. Time elapsed: {time_elapsed}. Raising exception.")
                raise Exception(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle alert {INITIALIZED}. Time elapsed: {time_elapsed}. Raising exception")
            else:
                logging.error(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle alert {INITIALIZED}. Time elapsed: {time_elapsed}. Return empty findings.")
                Utils.ERROR_CACHE.add(Utils.alert_error("Not initialized", "agent.handle_alert", traceback.format_exc()))
                return []


        global FINDINGS_CACHE_ALERT
        global DEBUG_ALERT_ENABLED
        findings = []
        if (Utils.is_beta() or Utils.is_beta_alt()) and DEBUG_ALERT_ENABLED:
            dt = parse_datetime_with_high_precision(alert_event.alert.created_at)
            unix_timestamp = (dt - datetime(1970, 1, 1)).total_seconds()
            unix_timestamp_sec = int(unix_timestamp)
            shard = unix_timestamp_sec % Utils.get_total_shards(CHAIN_ID)
            
            findings.append(Finding({
                'name': 'Debug Alert',
                'description': f'{shard},{CHAIN_ID},{alert_event.alert_hash},{alert_event.bot_id},{alert_event.alert.alert_id},observed)',
                'alert_id': "DEBUG-1",
                'type': FindingType.Info,
                'severity': FindingSeverity.Info,
                'metadata': {},
                'labels': []
            }))

        logging.info(f"{BOT_VERSION}: Handle alert called. Findings cache for alerts size: {len(FINDINGS_CACHE_ALERT)}")
        scam_findings = detect_scam(w3, alert_event)
        logging.info(f"{BOT_VERSION}: Added {len(scam_findings)} scam findings.") 
        FINDINGS_CACHE_ALERT.extend(scam_findings)
        logging.info(f"{BOT_VERSION}: Handle alert called. Findings cache for alerts size now: {len(FINDINGS_CACHE_ALERT)}")
        
        if not ('NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV')):
            persist_state()
            logging.info(f"{BOT_VERSION}: Persisted state")

        # To prevent exceeding call rate limits, Etherscan labels are checked for likely false positives only on the Ethereum chain.
        # The FP mitigation process occurs here, batching Etherscan API calls, rather than during finding creation.            
        if CHAIN_ID == 1:
            if len(FINDINGS_CACHE_ALERT) >= 5:
                FINDINGS_CACHE_ALERT = Utils.filter_out_likely_fps(FINDINGS_CACHE_ALERT)
                for finding in FINDINGS_CACHE_ALERT[0:10]:  # 10 findings per handle alert due to size limitation
                    if finding is not None:
                        findings.append(finding)
                FINDINGS_CACHE_ALERT = FINDINGS_CACHE_ALERT[10:]
        else:
            for finding in FINDINGS_CACHE_ALERT[0:10]:  # 10 findings per handle alert due to size limitation
                if finding is not None:
                    findings.append(finding)
            FINDINGS_CACHE_ALERT = FINDINGS_CACHE_ALERT[10:]

        logging.info(f"{BOT_VERSION}: Return {len(findings)} finding(s) to handleAlert.") 

        return findings

    return handle_alert


real_handle_alert = provide_handle_alert(web3)

def provide_handle_block(w3):
    logging.debug("provide_handle_block called")

    def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        logging.debug("handle_block with w3 called")
        global INITIALIZED
        global INITIALIZED_CALLED
        global INITIALIZATION_TIME
        if not INITIALIZED:
            time_elapsed = datetime.now() - INITIALIZATION_TIME
            if (time_elapsed > timedelta(minutes=5)):
                logging.error(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle block {INITIALIZED}. Time elapsed: {time_elapsed}. Raising exception.")
                raise Exception(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle block {INITIALIZED}. Time elapsed: {time_elapsed}. Raising exception.")
            else:
                logging.error(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle block {INITIALIZED}. Time elapsed: {time_elapsed}. Return empty finding.")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.handle_block", traceback.format_exc()))
                return []

        global REACTIVE_LIKELY_FPS
        global FINDINGS_CACHE_BLOCK
        findings = []

        timestamp = block_event.block.timestamp
        utc_timezone = pytz.UTC
        dt = datetime.fromtimestamp(timestamp, tz=utc_timezone)    
        logging.info(f"{BOT_VERSION}: handle block called with block timestamp {dt}")
        
        if Utils.is_beta() or Utils.is_beta_alt():
            logging.info(f"{BOT_VERSION}: Handle block called. Adding {Utils.ERROR_CACHE.len()} error findings.")
            findings.extend(Utils.ERROR_CACHE.get_all())
        Utils.ERROR_CACHE.clear()
        
        if dt.minute == 0:  # every hour
            logging.info(f"{BOT_VERSION}: Handle block on the 00 minute was called. Findings cache for blocks size: {len(FINDINGS_CACHE_BLOCK)}")
            manual_findings = emit_manual_finding(w3)
            logging.info(f"{BOT_VERSION}: Added {len(manual_findings)} manual findings.")
            FINDINGS_CACHE_BLOCK.extend(manual_findings)

            global DF_CONTRACT_SIGNATURES
            try:
                df_manual_list = Utils.get_manual_list()
                DF_CONTRACT_SIGNATURES = df_manual_list[df_manual_list['EntityType']=='Code']
                logging.info(f"{BOT_VERSION}: Loaded {len(DF_CONTRACT_SIGNATURES)} contract signatures.")
            except BaseException as e:
                logging.warning(f"{BOT_VERSION}: Failed to load contract signatures.")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.handle_block", traceback.format_exc()))

            logging.info(f"{BOT_VERSION}: Handle block on the hour was called. Findings cache for blocks size now: {len(FINDINGS_CACHE_BLOCK)}")
            
            persist_state()
            logging.info(f"{BOT_VERSION}: Persisted state")

        if dt.minute == 30:  # every hour
            logging.info(f"{BOT_VERSION}: Handle block on the 30 minute was called. Findings cache for blocks size: {len(FINDINGS_CACHE_BLOCK)}")
            fp_findings = emit_new_fp_finding(w3)                        
            logging.info(f"{BOT_VERSION}: Added {len(fp_findings)} fp findings.")
            FINDINGS_CACHE_BLOCK.extend(fp_findings)

            persist_state()
            logging.info(f"{BOT_VERSION}: Persisted state")

        if dt.minute == 45:  # every hour
            logging.info(f"{BOT_VERSION}: Handle block on the 45 minute was called. Findings cache for blocks size: {len(FINDINGS_CACHE_BLOCK)}")
            metamask_findings = emit_metamask_finding(w3)
            logging.info(f"{BOT_VERSION}: Added {len(metamask_findings)} metamask findings.")
            FINDINGS_CACHE_BLOCK.extend(metamask_findings)

            persist_state()
            logging.info(f"{BOT_VERSION}: Persisted state")
        
        reactive_fp_findings = update_reactive_likely_fps(w3, dt) 
        FINDINGS_CACHE_BLOCK.extend(reactive_fp_findings)

        for finding in FINDINGS_CACHE_BLOCK[0:25]:  # 25 findings per block due to size limitation
            if finding is not None:
                findings.append(finding)
        FINDINGS_CACHE_BLOCK = FINDINGS_CACHE_BLOCK[25:]

        logging.info(f"{BOT_VERSION}: Return {len(findings)} to handleBlock. FINDINGS_CACHE_BLOCK size: {len(FINDINGS_CACHE_BLOCK)}")

        return findings

    return handle_block


real_handle_block = provide_handle_block(web3)

def handle_alert(alert_event: forta_agent.alert_event.AlertEvent):
    logging.debug("handle_alert called")
    return real_handle_alert(alert_event)

def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)


def provide_handle_transaction(w3):
    logging.debug("provide_handle_transaction called")

    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        logging.debug("handle_transaction with w3 called")
        global INITIALIZED
        global INITIALIZED_CALLED
        global INITIALIZATION_TIME
        if not INITIALIZED:
            time_elapsed = datetime.now() - INITIALIZATION_TIME
            if (time_elapsed > timedelta(minutes=5)):
                logging.error(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle transaction {INITIALIZED}. Time elapsed: {time_elapsed}. Raising exception.")
                raise Exception(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle transaction {INITIALIZED}. Time elapsed: {time_elapsed}. Raising exception.")
            else:
                logging.warning(f"{BOT_VERSION}: Not initialized (initialized called: {INITIALIZED_CALLED}) handle transaction {INITIALIZED}. Time elapsed: {time_elapsed}. Return empty finding.")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.handle_transaction", traceback.format_exc()))
                return []
        
        global FINDINGS_CACHE_TRANSACTION
        findings = []
        logging.debug(f"{BOT_VERSION}: Handle transaction was called. Findings cache for transaction size: {len(FINDINGS_CACHE_TRANSACTION)}")
        contract_creation_findings = detect_scammer_contract_creation(w3, transaction_event)                        
        logging.debug(f"{BOT_VERSION}: Added {len(contract_creation_findings)} scammer contract creation findings.")
        FINDINGS_CACHE_TRANSACTION.extend(contract_creation_findings)

        logging.debug(f"{BOT_VERSION}: Handle transaction on the hour was called. Findings cache for transaction size now: {len(FINDINGS_CACHE_TRANSACTION)}")
            
        for finding in FINDINGS_CACHE_TRANSACTION[0:10]:  # 10 findings per block due to size limitation
            if finding is not None:
                findings.append(finding)
        FINDINGS_CACHE_TRANSACTION = FINDINGS_CACHE_TRANSACTION[10:]

        logging.debug(f"{BOT_VERSION}: Return {len(findings)} to handleTransaction.")

        return findings

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    logging.debug("handle_transaction called")
    return real_handle_transaction(transaction_event)