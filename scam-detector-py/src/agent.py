import logging
import sys
import requests
import os
from datetime import datetime, timedelta
import time
import pandas as pd
import numpy as np
import io
import traceback
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

import forta_agent
from forta_agent import get_json_rpc_url,  Finding, FindingType, FindingSeverity
from web3 import Web3

from src.constants import (BASE_BOTS, ALERTED_CLUSTERS_KEY, ALERTED_CLUSTERS_QUEUE_SIZE, ALERT_LOOKBACK_WINDOW_IN_DAYS, ENTITY_CLUSTER_BOTS,
                       FINDINGS_CACHE_ALERT_KEY, FINDINGS_CACHE_BLOCK_KEY, ALERTED_FP_CLUSTERS_KEY, FINDINGS_CACHE_TRANSACTION_KEY,
                       ALERTED_FP_CLUSTERS_QUEUE_SIZE, CONTRACT_SIMILARITY_BOTS, CONTRACT_SIMILARITY_BOT_THRESHOLDS, EOA_ASSOCIATION_BOTS,
                       EOA_ASSOCIATION_BOT_THRESHOLDS, PAIRCREATED_EVENT_ABI, SWAP_FACTORY_ADDRESSES, POOLCREATED_EVENT_ABI,
                       MODEL_ALERT_THRESHOLD_LOOSE, MODEL_ALERT_THRESHOLD_STRICT, MODEL_FEATURES, MODEL_NAME, DEBUG_ALERT_ENABLED)
from src.storage import s3_client, dynamo_table, get_secrets, bucket_name
from src.findings import ScamDetectorFinding
from src.blockchain_indexer_service import BlockChainIndexer
from src.forta_explorer import FortaExplorer
from src.base_bot_parser import BaseBotParser
from src.l2_cache import L2Cache
from src.utils import Utils

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
block_chain_indexer = BlockChainIndexer()
forta_explorer = FortaExplorer()

INITIALIZED = False
INITIALIZATION_TIME = datetime.now()
CHAIN_ID = -1
BOT_VERSION = Utils.get_bot_version()

ALERTED_CLUSTERS = dict()  # cluster -> alert_id
ALERTED_FP_CLUSTERS = dict()  # clusters -> alert_id (dummy val) which are considered FPs that have been alerted on
FINDINGS_CACHE_BLOCK = []
FINDINGS_CACHE_ALERT = []
FINDINGS_CACHE_TRANSACTION = []

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



def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    alert_config = {}
    global INITIALIZED

    try:
        reinitialize()

        global ALERTED_CLUSTERS
        alerted_clusters = load(CHAIN_ID, ALERTED_CLUSTERS_KEY)
        ALERTED_CLUSTERS = dict() if alerted_clusters is None else dict(alerted_clusters)

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
        sys.exit(1)

    return alert_config


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


def update_list(items: dict, max_size: int, item: str, alert_id: str, handler_type = ""):
    if item not in items.keys():
        items[item] = set()
    items[item].add(handler_type+alert_id)


    while len(items) > max_size:
        items.pop(0)  # remove oldest item


def put_entity_cluster(alert_created_at_str: str, address: str, cluster: str):
    global CHAIN_ID
    global BOT_VERSION

    logging.debug(f"putting entity clustering alert for {address} in dynamo DB")
    alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
    logging.debug(f"alert_created_at: {alert_created_at}")
    shard = Utils.get_shard(CHAIN_ID, alert_created_at)
    logging.debug(f"shard: {shard}")
    itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|entity_cluster|{address}"
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
        return
    else:
        logging.info(f"Successfully put alert in dynamoDB: {response}")
        return

# put in item alerts per cluster by shard id
# note, given sort key is part of the key, alerts with different hashes will result in different entries
# whereas alerts with the same hash will be overwritten
def put_alert(alert_event: forta_agent.alert_event.AlertEvent, cluster: str):
    global CHAIN_ID

    logging.debug(f"putting alert {alert_event.alert_hash} in dynamo DB")
    alert_created_at_str = alert_event.alert.created_at
    alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
    logging.debug(f"alert_created_at: {alert_created_at}")
    shard = Utils.get_shard(CHAIN_ID, alert_created_at)
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



def read_entity_clusters(address: str) -> dict:
    global CHAIN_ID

    entity_clusters = dict()
    for shard in range(Utils.get_total_shards(CHAIN_ID)):
        itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|entity_cluster|{address}"
        logging.debug(f"Reading entity clusters for address {address} from shard {shard}, itemId {itemId}")
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

    logging.debug(f"Reading alerts for cluster {cluster}")
    alert_items = []
    for shard in range(Utils.get_total_shards(CHAIN_ID)):
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
    logging.debug(f"Feature vector: {df_feature_vector.loc[0]}")

    predictions_proba = MODEL.predict_proba(df_feature_vector)[:, 1]
    return predictions_proba[0]


def already_alerted(cluster: str, alert_id: str, handler_type = ""):
    global ALERTED_CLUSTERS
    if cluster in ALERTED_CLUSTERS.keys():
        if (handler_type+alert_id) in ALERTED_CLUSTERS[cluster]:
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


def emit_combination_or_ml_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    findings = []
    global ALERTED_CLUSTERS
    global ALERTED_CLUSTERS_QUEUE_SIZE
    global BASE_BOTS
    global CHAIN_ID
    global BOT_VERSION

    scammer_addresses_dict = BaseBotParser.get_scammer_addresses(w3, alert_event)
    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got base bot alert (combination); extracted {len(scammer_addresses_dict.keys())} scammer addresses.")
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
        
        put_alert(alert_event, cluster)

        # get all alerts from dynamo for the cluster
        alert_list = read_alerts(cluster)  # list of tuple of (botId, alertId, alertHash)
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got {len(alert_list)} alerts from dynamo for cluster {cluster}")


        # first assess based on combination heuristic
        # assess whether the alerts map to combinations we would alert on; the focus is on ice phishing since that is a bit mor noisy
        #is_present = any(alertId_A == alert[1] for alert in alert_list)
        alert_condition_met_combination = False
        if any('ICE-PHISHING-PERMITTED-ERC20-TRANSFER' == alert[1] or 'ICE-PHISHING-SUSPICIOUS-TRANSFER' == alert[1] or 'ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS' == alert[1] or 'ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS' == alert[1] or
               'ICE-PHISHING-ERC20-APPROVAL-FOR-ALL' == alert[1] or 'ICE-PHISHING-ERC721-APPROVAL-FOR-ALL' == alert[1] or 'ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL' == alert[1] for alert in alert_list):
            if any('SLEEPMINT-3' == alert[1] for alert in alert_list):
                alert_condition_met_combination = True
            elif any('MALICIOUS-ACCOUNT-FUNDING' == alert[1] or 'UMBRA-RECEIVE' == alert[1] or 'CEX-FUNDING-1' == alert[1] or 'AK-AZTEC-PROTOCOL-FUNDING' == alert[1] or 'FUNDING-CHANGENOW-NEW-ACCOUNT' == alert[1] or 'FUNDING-TORNADO-CASH' == alert[1]
                     or 'TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION' == alert[1] or 'POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH' == alert[1] or 'MALICIOUS-ACCOUNT-FUNDING' == alert[1] for alert in alert_list):
                alert_condition_met_combination = True
            elif any('UNVERIFIED-CODE-CONTRACT-CREATION' == alert[1] or 'FLASHBOT-TRANSACTION' == alert[1] for alert in alert_list):
                alert_condition_met_combination = True
            elif any('SUSPICIOUS-TOKEN-CONTRACT-CREATION' == alert[1] for alert in alert_list):
                alert_condition_met_combination = True
            elif any('AE-MALICIOUS-ADDR' == alert[1] or 'forta-text-messages-possible-hack' == alert[1] for alert in alert_list):
                alert_condition_met_combination = True
            elif any('SCAM' in alert[1] for alert in alert_list):
                alert_condition_met_combination = True

        # second assess based on ML model
        alert_condition_met_ml = False
        feature_vector = build_feature_vector(alert_list, cluster)
        score = get_model_score(feature_vector)
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got score {score} for cluster {cluster}")
        model_threshold = MODEL_ALERT_THRESHOLD_LOOSE if Utils.is_beta() else MODEL_ALERT_THRESHOLD_STRICT
        if score>model_threshold:
            alert_condition_met_ml = True

        if alert_condition_met_combination or alert_condition_met_ml:
            #since this is a expensive function, will only check if we are about to raise an alert
            if Utils.is_fp(w3, cluster):
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} identified as FP; skipping")
                continue

            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
            for alert_id in get_scam_detector_alert_ids(alert_list):

                unique_alertIds = set(alert[1] for alert in alert_list)
                unique_alertHashes = set(alert[2] for alert in alert_list)
                created_at_datetime = datetime.strptime(alert_event.alert.created_at[0:19], "%Y-%m-%dT%H:%M:%S")
                if alert_condition_met_combination:
                    if already_alerted(cluster, alert_id, "combination") and not Utils.is_beta():  # alert repeatedly for beta version, but not prod version
                        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} already alerted on for {alert_id}; skipping")
                    else:
                        findings.append(ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, scammer_address_lower, created_at_datetime, created_at_datetime, scammer_contract_addresses, alert_event.alert.addresses, unique_alertIds, alert_id, unique_alertHashes, CHAIN_ID, "combination"))
                        update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, cluster, alert_id, "combination")
                if alert_condition_met_ml:
                    if already_alerted(cluster, alert_id, "combination") and not Utils.is_beta():  # alert repeatedly for beta version, but not prod version
                        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} already alerted on for {alert_id}; skipping")
                    else:
                        findings.append(ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, scammer_address_lower, created_at_datetime, created_at_datetime, scammer_contract_addresses, alert_event.alert.addresses, unique_alertIds, alert_id, unique_alertHashes, CHAIN_ID, "ml", score, feature_vector))
                        update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, cluster, alert_id, "ml")
                
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} added to findings. Findings size: {len(findings)}")
                

    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - return total findings: {len(findings)}")
    return findings

def emit_passthrough_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    findings = []
    global ALERTED_CLUSTERS
    global ALERTED_CLUSTERS_QUEUE_SIZE
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

        if Utils.is_fp(w3, cluster):
            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} identified as FP; skipping")
            continue

        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
        created_at_datetime = datetime.strptime(alert_event.alert.created_at[0:19], "%Y-%m-%dT%H:%M:%S")
        findings.append(ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, scammer_address_lower, created_at_datetime, created_at_datetime, scammer_contract_addresses, alert_event.alert.addresses, {alert_event.alert_id}, alert_id, {alert_event.alert_hash}, CHAIN_ID, "passthrough"))
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} added to findings. Findings size: {len(findings)}")
        update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, cluster, alert_id, "passthrough")

    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - return total findings: {len(findings)}")
    return findings

def emit_contract_similarity_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global ALERTED_CLUSTERS
    global ALERTED_CLUSTERS_QUEUE_SIZE
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
            if not Utils.is_fp(w3, scammer_address_lower):
                
                if not already_alerted(scammer_address_lower, "SCAM-DETECTOR-SIMILAR-CONTRACT"):
                    update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, scammer_address_lower, "SCAM-DETECTOR-SIMILAR-CONTRACT")
                    finding = ScamDetectorFinding.alert_similar_contract(block_chain_indexer, forta_explorer, alert_event.alert.alert_id, alert_event.alert_hash, alert_event.alert.metadata, CHAIN_ID)
                    if(finding is not None):
                        findings.append(finding)
                else:
                    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower} already alerted")
            else:
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower} in FP.")
    return findings


def emit_eoa_association_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global ALERTED_CLUSTERS
    global ALERTED_CLUSTERS_QUEUE_SIZE
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
            if not Utils.is_fp(w3, scammer_address_lower):
                if not already_alerted(scammer_address_lower, "SCAM-DETECTOR-SCAMMER-ASSOCIATION"):
                    update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, scammer_address_lower, "SCAM-DETECTOR-SCAMMER-ASSOCIATION")
                    #"central_node":"0x13549e22de184a881fe3d164612ef15f99f6d4b3",
                    # "central_node_alert_hash":"0xbda39ad1c0a53555587a8bc9c9f711f0cad81fe89ef235a6d79ee905bc70526c",
                    # "central_node_alert_id":"SCAM-DETECTOR-ICE-PHISHING",
                     
                    existing_scammer_eoa = alert_event.alert.metadata['central_node'] if 'central_node' in alert_event.alert.metadata else float(alert_event.alert.metadata['centralNode'])
                    original_alert_hash = alert_event.alert.metadata['central_node_alert_hash'] if 'central_node_alert_hash' in alert_event.alert.metadata else float(alert_event.alert.metadata['centralNodeAlertHash'])
                    original_alert_id = alert_event.alert.metadata['central_node_alert_id'] if 'central_node_alert_id' in alert_event.alert.metadata else float(alert_event.alert.metadata['centralNodeAlertId'])

                    finding = ScamDetectorFinding.scammer_association(block_chain_indexer, forta_explorer, scammer_address_lower, model_confidence, alert_event.alert.alert_id, alert_event.alert_hash, existing_scammer_eoa, original_alert_id, original_alert_hash, CHAIN_ID)
                    if(finding is not None):
                        findings.append(finding)
                else:
                    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower} already alerted")
            else:
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - address {scammer_address_lower} in FP.")
    return findings

def emit_manual_finding(w3, test = False) -> list:
    global ALERTED_CLUSTERS
    global CHAIN_ID
    findings = []

    if CHAIN_ID == -1:
        logging.error("Chain ID not set")
        raise Exception("Chain ID not set")

    res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/Scam-Detector-ML/scam-detector-py/manual_alert_list.tsv')
    logging.info(f"Manual finding: made request to fetch manual alerts: {res.status_code}")
    content = res.content.decode('utf-8') if res.status_code == 200 else open('manual_alert_list.tsv', 'r').read()
    df_manual_findings = pd.read_csv(io.StringIO(content), sep='\t')
    for index, row in df_manual_findings.iterrows():
        chain_id = -1
        try:
            chain_id_float = row['Chain ID']
            chain_id = int(chain_id_float)
        except Exception as e:
            logging.warning("Manual finding: Failed to get chain ID from manual finding")
            continue

        if chain_id != CHAIN_ID:
            logging.info("Manual finding: Manual entry doesnt match chain ID.")
            continue

        try:
            scammer_address_lower = row['Address'].lower().strip()
            cluster = scammer_address_lower
            logging.info(f"Manual finding: Have manual entry for {scammer_address_lower}")
            entity_clusters = read_entity_clusters(scammer_address_lower)
            if scammer_address_lower in entity_clusters.keys():
                cluster = entity_clusters[scammer_address_lower]

            if Utils.is_contract(w3, cluster):
                logging.info(f"Manual finding: Address {cluster} is a contract")
                continue

            threat_category = "unknown" if 'nan' in str(row["Threat category"]) else row['Threat category']
            alert_id_threat_category = threat_category.upper().replace(" ", "-")
            alert_id = "SCAM-DETECTOR-MANUAL-"+alert_id_threat_category
            if not already_alerted(scammer_address_lower, alert_id):
                logging.info(f"Manual finding: Emitting manual finding for {cluster}")
                tweet = "" if 'nan' in str(row["Tweet"]) else row['Tweet']
                account = "" if 'nan' in str(row["Account"]) else row['Account']
                update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, cluster, alert_id)
                findings.append(ScamDetectorFinding.scam_finding_manual(block_chain_indexer, forta_explorer, cluster, threat_category, account + " " + tweet, chain_id))
                logging.info(f"Findings count {len(findings)}")
                persist_state()

                if test:
                    break
            else:
                logging.info(f"Manual finding: Already alerted on {scammer_address_lower}")
        except Exception as e:
            logging.warning(f"Manual finding: Failed to process manual finding: {e} : {traceback.format_exc()}")
            continue

    return findings

# clear cache flag for perf testing
def detect_scam(w3, alert_event: forta_agent.alert_event.AlertEvent, clear_state_flag = False) -> list:
    
    if clear_state_flag:
        clear_state()

    global ENTITY_CLUSTER_BOTS
    global CHAIN_ID
    global ALERTED_CLUSTERS
    global BASE_BOTS

    
    findings = []
    try:
        start = time.time()

        if CHAIN_ID == -1:
            reinitialize()
            if CHAIN_ID == -1:
                logging.error(f"{BOT_VERSION}: CHAIN_ID not set")
                raise Exception("CHAIN_ID not set")

        chain_id = int(alert_event.chain_id) 
        if chain_id == CHAIN_ID:
            # got alert from the right chain
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - received alert for proper chain {CHAIN_ID}")

            # TODO - change to using dynamo as the bot shards
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
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} is contract similarity alert")
                return emit_contract_similarity_finding(w3, alert_event)
            elif in_list(alert_event, EOA_ASSOCIATION_BOTS):
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} is eoa association alert")
                return emit_eoa_association_finding(w3, alert_event)
            elif alert_logic(alert_event, BASE_BOTS) == "PassThrough":
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - is passthrough alert")
                findings = []
                findings.extend(emit_combination_or_ml_finding(w3, alert_event)) # pushing passthrough to assess how well we would do with an ML approach; this is more for testing purposes right now
                findings.extend(emit_passthrough_finding(w3, alert_event))
                return findings
            elif alert_logic(alert_event, BASE_BOTS) == "Combination":  
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - is combination alert")
                return emit_combination_or_ml_finding(w3, alert_event)
            else:
                logging.warning(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got base bot alert; not part of subscription")
        else:
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - wrong chain {chain_id} for bot {CHAIN_ID}")

        end = time.time()
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.alert_id} {alert_event.chain_id} processing took {end - start} seconds")
    except BaseException as e:
        logging.warning(f"{BOT_VERSION}: alert {alert_event.alert_hash} - Exception in process_alert {alert_event.alert_hash}: {e} - {traceback.format_exc()}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} - Raising exception to expose error to scannode")
            raise e

    return findings

# This function emits FPs for each address in the static list maintained by the Forta Community residing on github
# FPs are processed by emitting a label with the remove flag set to True; note, the label needs to match the original label, so we need to pull the original label from the API
# Further, given a label - through propagation - could expand out, the algorithm needs to assess what labels were set due to propagation and remove those as well
def emit_new_fp_finding(w3) -> list:
    global ALERTED_FP_CLUSTERS
    global CHAIN_ID
    global ALERTED_FP_CLUSTERS_QUEUE_SIZE
    global FINDINGS_CACHE_BLOCK

    if CHAIN_ID == -1:
        reinitialize()
        if CHAIN_ID == -1:
            logging.error(f"{BOT_VERSION}: CHAIN_ID not set")
            raise Exception("CHAIN_ID not set")
    findings = []

    similar_contract_labels = None
    scammer_association_labels = None


    try:
        res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/main/scam-detector-py/fp_list.csv')
        content = res.content.decode('utf-8') if res.status_code == 200 else open('fp_list.csv', 'r').read()
        df_fp = pd.read_csv(io.StringIO(content), sep=',')
        for index, row in df_fp.iterrows():
            chain_id = int(row['chain_id'])
            if chain_id != CHAIN_ID:
                continue
            cluster = row['address'].lower()
            if cluster not in ALERTED_FP_CLUSTERS.keys():
                update_list(ALERTED_FP_CLUSTERS, ALERTED_FP_CLUSTERS_QUEUE_SIZE, cluster, "SCAM-DETECTOR-FALSE-POSITIVE")
                for address in cluster.split(','):
                    if scammer_association_labels is None:
                        scammer_association_labels = get_scammer_association_labels(w3, forta_explorer)
                    if similar_contract_labels is None:
                        similar_contract_labels = get_similar_contract_labels(w3, forta_explorer)
                    
                    for (entity, label, metadata) in obtain_all_fp_labels(w3, address, block_chain_indexer, forta_explorer, similar_contract_labels, scammer_association_labels, CHAIN_ID):
                        logging.info(f"{BOT_VERSION}: Emitting FP mitigation finding for {entity} {label}")
                        update_list(ALERTED_FP_CLUSTERS, ALERTED_FP_CLUSTERS_QUEUE_SIZE, entity, "SCAM-DETECTOR-FALSE-POSITIVE")
                        findings.append(ScamDetectorFinding.alert_FP(w3, entity, label, metadata))
                        logging.info(f"{BOT_VERSION}: Findings count {len(FINDINGS_CACHE_BLOCK)}")
    except BaseException as e:
        logging.warning(f"{BOT_VERSION}: emit fp finding exception: {e} - {traceback.format_exc()}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"{BOT_VERSION}: emit fp finding exception:  - Raising exception to expose error to scannode")
            raise e

    return findings

def get_value(items: list, key: str):
    v = ''
    for item in items:
        if item.startswith(key):
            v = item.split('=')[1].lower()
            break
    return v

# contains from_entity, from_entity_deployer, to_entity, to_entity_deployer
def get_similar_contract_labels(w3, forta_explorer) -> pd.DataFrame:
    source_id = '0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8' if Utils.is_beta() else '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23'
    df_labels = forta_explorer.get_labels(source_id, datetime(2023,3,1), datetime.now(), label_query = "similar-contract")
    df_labels.rename(columns={'entity': 'to_entity'}, inplace=True)
    df_labels['from_entity'] = df_labels['metadata'].apply(lambda x: get_value(x, "associated_scammer_contract"))
    df_labels['deployer_info'] = df_labels['metadata'].apply(lambda x: get_value(x, "deployer_info"))
    df_labels['from_entity_deployer'] = df_labels['deployer_info'].apply(lambda x: x[216:216+42])
    df_labels['to_entity_deployer'] = df_labels['deployer_info'].apply(lambda x: x[9:9+42])
    df_labels['from_entity'] = df_labels['metadata'].apply(lambda x: get_value(x, "associated_scammer_contract"))
    # drop all but from_entity and to_entity
    df_labels.drop(df_labels.columns.difference(['from_entity', 'from_entity_deployer', 'to_entity', 'to_entity_deployer']), axis=1, inplace=True)                                      
    return df_labels



# contains from_entity and to_entity
def get_scammer_association_labels(w3, forta_explorer) -> pd.DataFrame:
    source_id = '0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8' if Utils.is_beta() else '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23'
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
# returns a tuple of (entity, label) where label consists of scammer-label/threat_category/handler_type or just scammer-label for older labels (pre 0.2.2)
def obtain_all_fp_labels(w3, starting_address: str, block_chain_indexer, forta_explorer, similar_contract_labels: pd.DataFrame, scammer_association_labels: pd.DataFrame, chain_id: int) -> set:
    global ALERTED_FP_CLUSTERS
    global ALERTED_FP_CLUSTERS

    logging.info(f"{BOT_VERSION}: {starting_address} obtain_all_fp_labels")

    source_id = '0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8' if Utils.is_beta() else '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23'

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
                if any("contract" in s for s in row['metadata']):
                    logging.info(f"{BOT_VERSION}: {starting_address} adding FP label {row['labelstr']} for contract {address}")
                    fp_labels.add((address,row["labelstr"],row['metadata']))

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
                if any("EOA" in s for s in row['metadata']):
                    logging.info(f"{BOT_VERSION}: {starting_address} adding FP label {row['labelstr']} for contract {address}")
                    fp_labels.add((address, row["labelstr"],row['metadata']))

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

    source_id = '0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8' if Utils.is_beta() else '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23'
    labels_df = FortaExplorer.get_labels(source_id, datetime(2023,1,1), datetime.now(), entity = address.lower())
    for index, row in labels_df.iterrows():
        if any("EOA" in s for s in row['metadata']):
            threat_category = row["labelstr"]
            return (threat_category, row["alertHash"])

    return ("", "")


def detect_scammer_contract_creation(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    findings = []

    if transaction_event.to is None:
        nonce = transaction_event.transaction.nonce
        created_contract_address = Utils.calc_contract_address(w3, transaction_event.from_, nonce)
        original_threat_category, original_alert_hash = get_original_threat_category_alert_hash(transaction_event.from_)
        if original_threat_category != "":
            findings.append(ScamDetectorFinding.scammer_contract_deployment(transaction_event.from_, created_contract_address.lower(), original_threat_category, original_alert_hash, CHAIN_ID))
        
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


    return findings


def clear_state():
    # delete cache file
    L2Cache.remove(CHAIN_ID, ALERTED_CLUSTERS_KEY)
    L2Cache.remove(CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
    L2Cache.remove(CHAIN_ID, FINDINGS_CACHE_BLOCK_KEY)
    L2Cache.remove(CHAIN_ID, FINDINGS_CACHE_ALERT_KEY)
    L2Cache.remove(CHAIN_ID, FINDINGS_CACHE_TRANSACTION_KEY)
    
    Utils.FP_MITIGATION_ADDRESSES = set()
    Utils.CONTRACT_CACHE = dict()

def persist_state():
    global ALERTED_CLUSTERS
    global ALERTED_CLUSTERS_KEY

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
    persist(ALERTED_CLUSTERS, CHAIN_ID, ALERTED_CLUSTERS_KEY)
    persist(ALERTED_FP_CLUSTERS, CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
    persist(FINDINGS_CACHE_BLOCK, CHAIN_ID, FINDINGS_CACHE_BLOCK_KEY)
    persist(FINDINGS_CACHE_ALERT, CHAIN_ID, FINDINGS_CACHE_ALERT_KEY)
    persist(FINDINGS_CACHE_TRANSACTION, CHAIN_ID, FINDINGS_CACHE_TRANSACTION_KEY)

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
        global INITIALIZATION_TIME
        if not INITIALIZED:
            time_elapsed = datetime.now() - INITIALIZATION_TIME
            if (time_elapsed > timedelta(minutes=5)):
                logging.error(f"{BOT_VERSION}: Not initialized handle alert {INITIALIZED}. Time elapsed: {time_elapsed}. Exiting.")
                sys.exit(1)
            else:
                logging.warning(f"{BOT_VERSION}: Not initialized handle alert {INITIALIZED}. Time elapsed: {time_elapsed}. Returning.")
                return []


        global FINDINGS_CACHE_ALERT
        global DEBUG_ALERT_ENABLED
        findings = []
        if Utils.is_beta() and DEBUG_ALERT_ENABLED:
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

        for finding in FINDINGS_CACHE_ALERT[0:10]:  # 10 findings per handle alert due to size limitation
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
        global INITIALIZATION_TIME
        if not INITIALIZED:
            time_elapsed = datetime.now() - INITIALIZATION_TIME
            if (time_elapsed > timedelta(minutes=5)):
                logging.error(f"{BOT_VERSION}: Not initialized handle block {INITIALIZED}. Time elapsed: {time_elapsed}. Exiting.")
                sys.exit(1)
            else:
                logging.warning(f"{BOT_VERSION}: Not initialized handle block {INITIALIZED}. Time elapsed: {time_elapsed}. Returning.")
                return []

        global FINDINGS_CACHE_BLOCK
        findings = []
        dt = datetime.fromtimestamp(block_event.block.timestamp)
        logging.info(f"{BOT_VERSION}: handle block called with block timestamp {dt}")
        if dt.minute == 0:  # every hour
            logging.info(f"{BOT_VERSION}: Handle block on the hour was called. Findings cache for blocks size: {len(FINDINGS_CACHE_BLOCK)}")
            fp_findings = emit_new_fp_finding(w3)                        
            logging.info(f"{BOT_VERSION}: Added {len(fp_findings)} fp findings.")
            FINDINGS_CACHE_BLOCK.extend(fp_findings)
            manual_findings = emit_manual_finding(w3)
            logging.info(f"{BOT_VERSION}: Added {len(manual_findings)} manual findings.")
            FINDINGS_CACHE_BLOCK.extend(manual_findings)

            logging.info(f"{BOT_VERSION}: Handle block on the hour was called. Findings cache for blocks size now: {len(FINDINGS_CACHE_BLOCK)}")
            
            persist_state()
            logging.info(f"{BOT_VERSION}: Persisted state")
        
        for finding in FINDINGS_CACHE_BLOCK[0:10]:  # 10 findings per block due to size limitation
            findings.append(finding)
        FINDINGS_CACHE_BLOCK = FINDINGS_CACHE_BLOCK[10:]

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
        global INITIALIZATION_TIME
        if not INITIALIZED:
            time_elapsed = datetime.now() - INITIALIZATION_TIME
            if (time_elapsed > timedelta(minutes=5)):
                logging.error(f"{BOT_VERSION}: Not initialized handle transaction {INITIALIZED}. Time elapsed: {time_elapsed}. Exiting.")
                sys.exit(1)
            else:
                logging.warning(f"{BOT_VERSION}: Not initialized handle transaction {INITIALIZED}. Time elapsed: {time_elapsed}. Returning.")
                return []
        
        global FINDINGS_CACHE_TRANSACTION
        findings = []
        logging.debug(f"{BOT_VERSION}: Handle transaction was called. Findings cache for transaction size: {len(FINDINGS_CACHE_TRANSACTION)}")
        contract_creation_findings = detect_scammer_contract_creation(w3, transaction_event)                        
        logging.debug(f"{BOT_VERSION}: Added {len(contract_creation_findings)} scammer contract creation findings.")
        FINDINGS_CACHE_BLOCK.extend(contract_creation_findings)

        logging.debug(f"{BOT_VERSION}: Handle transaction on the hour was called. Findings cache for transaction size now: {len(FINDINGS_CACHE_TRANSACTION)}")
            
        for finding in FINDINGS_CACHE_TRANSACTION[0:10]:  # 10 findings per block due to size limitation
            findings.append(finding)
        FINDINGS_CACHE_TRANSACTION = FINDINGS_CACHE_TRANSACTION[10:]

        logging.debug(f"{BOT_VERSION}: Return {len(findings)} to handleTransaction.")
        return findings

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    logging.debug("handle_transaction called")
    return real_handle_transaction(transaction_event)