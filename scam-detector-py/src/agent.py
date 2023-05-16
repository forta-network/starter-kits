import logging
import sys
import requests
import os
from datetime import datetime
import time
import pandas as pd
import numpy as np
import io
import traceback


import forta_agent
from forta_agent import get_json_rpc_url,  Finding, FindingType, FindingSeverity
from web3 import Web3

from src.constants import (BASE_BOTS, ALERTED_CLUSTERS_KEY, ALERTED_CLUSTERS_QUEUE_SIZE, ALERT_LOOKBACK_WINDOW_IN_DAYS, ENTITY_CLUSTER_BOTS,
                       FINDINGS_CACHE_ALERT_KEY, FINDINGS_CACHE_BLOCK_KEY, ALERTED_FP_CLUSTERS_KEY, 
                       ALERTED_FP_CLUSTERS_QUEUE_SIZE, CONTRACT_SIMILARITY_BOTS, CONTRACT_SIMILARITY_BOT_THRESHOLDS)
from src.storage import s3_client, dynamo_table, get_secrets, bucket_name
from src.findings import ScamDetectorFinding
from src.blockchain_indexer_service import BlockChainIndexer
from src.base_bot_parser import BaseBotParser
from src.l2_cache import L2Cache
from src.utils import Utils

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
block_chain_indexer = BlockChainIndexer()

INITIALIZED = False
CHAIN_ID = -1
BOT_VERSION = Utils.get_bot_version()

ALERTED_CLUSTERS = set()  # cluster that have been alerted on
ALERTED_FP_CLUSTERS = set()  # clusters which are considered FPs that have been alerted on
FINDINGS_CACHE_BLOCK = []
FINDINGS_CACHE_ALERT = []

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
    global INITIALIZED

    reinitialize()

    global ALERTED_CLUSTERS
    alerted_clusters = load(CHAIN_ID, ALERTED_CLUSTERS_KEY)
    ALERTED_CLUSTERS = set() if alerted_clusters is None else set(alerted_clusters)

    global ALERTED_FP_CLUSTERS
    alerted_fp_addresses = load(CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
    ALERTED_FP_CLUSTERS = set() if alerted_fp_addresses is None else alerted_fp_addresses

    global FINDINGS_CACHE_BLOCK
    findings_cache_block = load(CHAIN_ID, FINDINGS_CACHE_BLOCK_KEY)
    FINDINGS_CACHE_BLOCK = [] if findings_cache_block is None else findings_cache_block

    global FINDINGS_CACHE_ALERT
    findings_cache_alert = load(CHAIN_ID, FINDINGS_CACHE_ALERT_KEY)
    FINDINGS_CACHE_ALERT = [] if findings_cache_alert is None else findings_cache_alert

    

    # subscribe to the base bots, FP mitigation and entity clustering bot
    global BASE_BOTS
    subscription_json = []
    for botId, alertId, alert_logic, target_alert_id in BASE_BOTS:
        subscription_json.append({"botId": botId, "alertId": alertId, "chainId": CHAIN_ID})

    alert_config = {"alertConfig": {"subscriptions": subscription_json}}
    logging.info(f"{BOT_VERSION}: Initializing scam detector bot. Subscribed to bots successfully: {alert_config}")
    logging.info(f"{BOT_VERSION}: Initialized scam detector bot.")
    INITIALIZED = True
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


def update_list(items: set, max_size: int, item: str):
    items.add(item.lower())

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





def emit_combination_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
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
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got scammer address {scammer_address_lower}")
        cluster = scammer_address_lower
        entity_cluster = read_entity_clusters(scammer_address_lower)
        if scammer_address_lower in entity_cluster.keys():
            cluster = entity_cluster[scammer_address_lower]
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got alert for cluster {cluster}")

        if Utils.is_contract(w3, cluster):
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} is contract, skipping")
            continue

        if cluster in ALERTED_CLUSTERS:
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} already alerted on; skipping")
            continue

        put_alert(alert_event, cluster)

        # get all alerts from dynamo for the cluster
        alert_list = read_alerts(cluster)  # list of tuple of (botId, alertId, alertHash)
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got {len(alert_list)} alerts from dynamo for cluster {cluster}")

        # assess whether the alerts map to combinations we would alert on; the focus is on ice phishing since that is a bit mor noisy
        #is_present = any(alertId_A == alert[1] for alert in alert_list)
        alert_condition_met = False
        if any('ICE-PHISHING-PERMITTED-ERC20-TRANSFER' == alert[1] or 'ICE-PHISHING-SUSPICIOUS-TRANSFER' == alert[1] or 'ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS' == alert[1] or 'ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS' == alert[1] or
               'ICE-PHISHING-ERC20-APPROVAL-FOR-ALL' == alert[1] or 'ICE-PHISHING-ERC721-APPROVAL-FOR-ALL' == alert[1] or 'ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL' == alert[1] for alert in alert_list):
            if any('SLEEPMINT-3' == alert[1] for alert in alert_list):
                alert_condition_met = True
            elif any('MALICIOUS-ACCOUNT-FUNDING' == alert[1] or 'UMBRA-RECEIVE' == alert[1] or 'CEX-FUNDING-1' == alert[1] or 'AK-AZTEC-PROTOCOL-FUNDING' == alert[1] or 'FUNDING-CHANGENOW-NEW-ACCOUNT' == alert[1] or 'FUNDING-TORNADO-CASH' == alert[1]
                     or 'TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION' == alert[1] or 'POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH' == alert[1] or 'MALICIOUS-ACCOUNT-FUNDING' == alert[1] for alert in alert_list):
                alert_condition_met = True
            elif any('UNVERIFIED-CODE-CONTRACT-CREATION' == alert[1] or 'FLASHBOT-TRANSACTION' == alert[1] for alert in alert_list):
                alert_condition_met = True
            elif any('SUSPICIOUS-TOKEN-CONTRACT-CREATION' == alert[1] for alert in alert_list):
                alert_condition_met = True
            elif any('AE-MALICIOUS-ADDR' == alert[1] or 'forta-text-messages-possible-hack' == alert[1] for alert in alert_list):
                alert_condition_met = True
            elif any('SCAM' in alert[1] for alert in alert_list):
                alert_condition_met = True

        if alert_condition_met:
            #since this is a expensive function, will only check if we are about to raise an alert
            if Utils.is_fp(w3, cluster):
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} identified as FP; skipping")
                continue

            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
            alert_id = "SCAM-DETECTOR-ICE-PHISHING"
            unique_alertIds = set(alert[1] for alert in alert_list)
            unique_alertHashes = set(alert[2] for alert in alert_list)
            created_at_datetime = datetime.strptime(alert_event.alert.created_at[0:19], "%Y-%m-%dT%H:%M:%S")
            findings.append(ScamDetectorFinding.scam_finding(block_chain_indexer, scammer_address_lower, created_at_datetime, created_at_datetime, alert_event.alert.addresses, unique_alertIds, alert_id, unique_alertHashes, CHAIN_ID))
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} added to findings. Findings size: {len(findings)}")
            update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, cluster)

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
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got scammer address {scammer_address_lower}")
        cluster = scammer_address_lower
        entity_cluster = read_entity_clusters(scammer_address_lower)
        if scammer_address_lower in entity_cluster.keys():
            cluster = entity_cluster[scammer_address_lower]
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - got alert for cluster {cluster}")

        if Utils.is_contract(w3, cluster):
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} is contract, skipping")
            continue

        if cluster in ALERTED_CLUSTERS:
            logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} already alerted on; skipping")
            continue

        if Utils.is_fp(w3, cluster):
            logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} identified as FP; skipping")
            continue

        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} not in FP mitigation clusters")
        alert_id_target = alert_target(alert_event, BASE_BOTS)
        alert_id = "SCAM-DETECTOR-ADDRESS-POISONER" if scammer_addresses_dict[scammer_address]["address_information"] == "poisoner" else alert_id_target
        created_at_datetime = datetime.strptime(alert_event.alert.created_at[0:19], "%Y-%m-%dT%H:%M:%S")
        findings.append(ScamDetectorFinding.scam_finding(block_chain_indexer, scammer_address_lower, created_at_datetime, created_at_datetime, alert_event.alert.addresses, {alert_event.alert_id}, alert_id, {alert_event.alert_hash}, CHAIN_ID))
        logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - cluster {cluster} added to findings. Findings size: {len(findings)}")
        update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, cluster)

    logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - return total findings: {len(findings)}")
    return findings

def emit_contract_similarity_finding(w3, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    global ALERTED_CLUSTERS
    global ALERTED_CLUSTERS_QUEUE_SIZE
    global CONTRACT_SIMILARITY_BOT_THRESHOLDS

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
                if scammer_address_lower not in ALERTED_CLUSTERS:
                    update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, scammer_address_lower)
                    finding = ScamDetectorFinding.alert_similar_contract(block_chain_indexer, alert_event.alert.metadata, CHAIN_ID)
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

        scammer_address_lower = row['Address'].lower().strip()
        cluster = scammer_address_lower
        logging.info(f"Manual finding: Have manual entry for {scammer_address_lower}")
        entity_clusters = read_entity_clusters(scammer_address_lower)
        if scammer_address_lower in entity_clusters.keys():
            cluster = entity_clusters[scammer_address_lower]

        if Utils.is_contract(w3, cluster):
            logging.info(f"Manual finding: Address {cluster} is a contract")
            continue

        if cluster not in ALERTED_CLUSTERS:
            logging.info(f"Manual finding: Emitting manual finding for {cluster}")
            update_list(ALERTED_CLUSTERS, ALERTED_CLUSTERS_QUEUE_SIZE, cluster)
            tweet = "" if 'nan' in str(row["Tweet"]) else row['Tweet']
            findings.append(ScamDetectorFinding.scam_finding_manual(block_chain_indexer, cluster, row['Threat category'], row['Account'] + " " + tweet, chain_id))
            logging.info(f"Findings count {len(findings)}")
            persist_state()

            if test:
                break
        else:
            logging.info(f"Manual finding: Already alerted on {scammer_address_lower}")

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

        chain_id = int(alert_event.chain_id) if (alert_event.alert.source.block.chain_id is None or alert_event.alert.source.block.chain_id == 0) else int(alert_event.alert.source.block.chain_id)
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
            elif alert_logic(alert_event, BASE_BOTS) == "PassThrough":
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - is passthrough alert")
                return emit_passthrough_finding(w3, alert_event)
            elif alert_logic(alert_event, BASE_BOTS) == "Combination":
                logging.info(f"{BOT_VERSION}: alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} - is combination alert")
                return emit_combination_finding(w3, alert_event)
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

    try:
        res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/main/scam-detector-py/fp_list.csv')
        content = res.content.decode('utf-8') if res.status_code == 200 else open('fp_list.csv', 'r').read()
        df_fp = pd.read_csv(io.StringIO(content), sep=',')
        for index, row in df_fp.iterrows():
            chain_id = int(row['chain_id'])
            if chain_id != CHAIN_ID:
                continue
            cluster = row['address'].lower()
            if cluster not in ALERTED_FP_CLUSTERS:
                logging.info(f"{BOT_VERSION}: Emitting FP mitigation finding")
                update_list(ALERTED_FP_CLUSTERS, ALERTED_FP_CLUSTERS_QUEUE_SIZE, cluster)
                findings.append(ScamDetectorFinding.alert_FP(w3, cluster))
                logging.info(f"{BOT_VERSION}: Findings count {len(FINDINGS_CACHE_BLOCK)}")
    except BaseException as e:
        logging.warning(f"{BOT_VERSION}: emit fp finding exception: {e} - {traceback.format_exc()}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"{BOT_VERSION}: emit fp finding exception:  - Raising exception to expose error to scannode")
            raise e

    return findings

def clear_state():
    # delete cache file
    L2Cache.remove(CHAIN_ID, ALERTED_CLUSTERS_KEY)
    L2Cache.remove(CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
    L2Cache.remove(CHAIN_ID, FINDINGS_CACHE_BLOCK_KEY)
    L2Cache.remove(CHAIN_ID, FINDINGS_CACHE_ALERT_KEY)
    
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

    global CHAIN_ID

    start = time.time()
    persist(ALERTED_CLUSTERS, CHAIN_ID, ALERTED_CLUSTERS_KEY)
    persist(ALERTED_FP_CLUSTERS, CHAIN_ID, ALERTED_FP_CLUSTERS_KEY)
    persist(FINDINGS_CACHE_BLOCK, CHAIN_ID, FINDINGS_CACHE_BLOCK_KEY)
    persist(FINDINGS_CACHE_ALERT, CHAIN_ID, FINDINGS_CACHE_ALERT_KEY)

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
        if not INITIALIZED:
            raise Exception("Not initialized")

        global FINDINGS_CACHE_ALERT
        findings = []
        if Utils.is_beta():
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
        if not INITIALIZED:
            raise Exception("Not initialized")
        global FINDINGS_CACHE_BLOCK
        findings = []
        if datetime.now().minute == 0:  # every hour
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

        logging.info(f"{BOT_VERSION}: Return {len(findings)} to handleBlock.")
        return findings

    return handle_block


real_handle_block = provide_handle_block(web3)

def handle_alert(alert_event: forta_agent.alert_event.AlertEvent):
    logging.debug("handle_alert called")
    return real_handle_alert(alert_event)

def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)