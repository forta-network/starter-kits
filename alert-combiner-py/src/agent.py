import logging
import sys
from datetime import datetime 

import traceback
import forta_agent
import pandas as pd
import time
import os
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3
from forta_agent import FindingSeverity

from src.findings import AlertCombinerFinding
from src.constants import (BASE_BOTS, ENTITY_CLUSTER_BOT_ALERT_ID, ALERTED_CLUSTERS_MAX_QUEUE_SIZE,
                           FP_MITIGATION_BOTS, ENTITY_CLUSTER_BOT, ANOMALY_SCORE_THRESHOLD_STRICT, ANOMALY_SCORE_THRESHOLD_LOOSE,
                           MIN_ALERTS_COUNT, ALERTED_CLUSTERS_STRICT_KEY, ALERTED_CLUSTERS_LOOSE_KEY, VICTIM_IDENTIFICATION_BOT, VICTIM_IDENTIFICATION_BOT_ALERT_IDS, DEFAULT_ANOMALY_SCORE, HIGHLY_PRECISE_BOTS,
                           ALERTED_CLUSTERS_FP_MITIGATED_KEY, END_USER_ATTACK_BOTS, POLYGON_VALIDATOR_ALERT_COUNT_THRESHOLD)
from src.L2Cache import L2Cache
from src.storage import s3_client, dynamo_table, get_secrets
from src.blockchain_indexer_service import BlockChainIndexer
from src.utils import Utils
from src.dynamo_utils import DynamoUtils


web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
block_chain_indexer = BlockChainIndexer()

INITIALIZED = False
CHAIN_ID = -1

CONTRACT_CACHE = dict()  # address -> is_contract
ALERTED_CLUSTERS_STRICT = []  # cluster
ALERTED_CLUSTERS_LOOSE = []  # cluster
ALERTED_CLUSTERS_FP_MITIGATED = []  # cluster
ALERT_ID_STAGE_MAPPING = dict()  # (bot_id, alert_id) -> stage

s3 = None
dynamo = None

root = logging.getLogger()
root.setLevel(logging.DEBUG)
logging.getLogger('botocore').setLevel(logging.WARNING)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    logging.debug('initializing')
    global INITIALIZED

    reinitialize()

    global ALERT_ID_STAGE_MAPPING
    ALERT_ID_STAGE_MAPPING = dict([((bot_id, alert_id), stage) for bot_id, alert_id, stage in BASE_BOTS])

    global ALERTED_CLUSTERS_FP_MITIGATED
    alerted_clusters = load(CHAIN_ID, ALERTED_CLUSTERS_FP_MITIGATED_KEY)
    ALERTED_CLUSTERS_FP_MITIGATED = [] if alerted_clusters is None else list(alerted_clusters)

    global ALERTED_CLUSTERS_STRICT
    alerted_clusters = load(CHAIN_ID, ALERTED_CLUSTERS_STRICT_KEY)
    ALERTED_CLUSTERS_STRICT = [] if alerted_clusters is None else list(alerted_clusters)

    global ALERTED_CLUSTERS_LOOSE
    alerted_clusters = load(CHAIN_ID, ALERTED_CLUSTERS_LOOSE_KEY)
    ALERTED_CLUSTERS_LOOSE = [] if alerted_clusters is None else list(alerted_clusters)

    global CONTRACT_CACHE
    CONTRACT_CACHE = {}

    subscription_json = []
    for bot, alertId, stage in BASE_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId, "chainId": CHAIN_ID})
        if CHAIN_ID in [10, 42161]:
            subscription_json.append({"botId": bot, "alertId": alertId, "chainId": 1})
   
    for bot, alertId in FP_MITIGATION_BOTS:
        subscription_json.append({"botId": bot, "alertId": alertId, "chainId": CHAIN_ID})
        if CHAIN_ID in [10, 42161]:
            subscription_json.append({"botId": bot, "alertId": alertId, "chainId": 1})

    for bot in END_USER_ATTACK_BOTS:
        subscription_json.append({"botId": bot, "chainId": CHAIN_ID})
        if CHAIN_ID in [10, 42161]:
            subscription_json.append({"botId": bot, "chainId": 1})

    subscription_json.append({"botId": ENTITY_CLUSTER_BOT, "alertId": ENTITY_CLUSTER_BOT_ALERT_ID, "chainId": CHAIN_ID})

    subscription_json.append({"botId": VICTIM_IDENTIFICATION_BOT, "alertId": VICTIM_IDENTIFICATION_BOT_ALERT_IDS[0], "chainId": CHAIN_ID})

    subscription_json.append({"botId": VICTIM_IDENTIFICATION_BOT, "alertId": VICTIM_IDENTIFICATION_BOT_ALERT_IDS[1], "chainId": CHAIN_ID})

    if CHAIN_ID in [10, 42161]:
        subscription_json.append({"botId": ENTITY_CLUSTER_BOT, "alertId": ENTITY_CLUSTER_BOT_ALERT_ID, "chainId": 1})
        subscription_json.append({"botId": VICTIM_IDENTIFICATION_BOT, "alertId": VICTIM_IDENTIFICATION_BOT_ALERT_IDS[0], "chainId": 1})
        subscription_json.append({"botId": VICTIM_IDENTIFICATION_BOT, "alertId": VICTIM_IDENTIFICATION_BOT_ALERT_IDS[1], "chainId": 1})

    INITIALIZED = True

    return {"alertConfig": {"subscriptions": subscription_json}}

def reinitialize():
    global CHAIN_ID
    global s3
    global dynamo

    try:
        # initialize dynamo DB
        if dynamo is None:
            secrets = get_secrets()
            s3 = s3_client(secrets)
            dynamo = dynamo_table(secrets)
            logging.info(f"Initialized dynamo DB successfully.")
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e
        
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
    


def get_pot_attacker_addresses(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    """
    this function returns the attacker addresses from the labels
    :param alert_event: alert event with labels and addresses arrray
    :return: attacker_addresses: list of attacker addresses
    """
    pot_attacker_addresses = []
    try:
        for label in alert_event.alert.labels:
            if label.label is not None and ('attack' in label.label.lower() or 'exploit' in label.label.lower() or 'scam' in label.label.lower()):
                pot_attacker_addresses.append(label.entity)
        logging.info(f"alert {alert_event.alert_hash} {alert_event.alert_id} - Analysing {len(pot_attacker_addresses)} pot attacker addresses obtained from labels")

        for key in alert_event.alert.metadata.keys():
            if key is not None and ('attack' in key.lower() or 'exploit' in key.lower() or 'scam' in key.lower() or 'caller' in key.lower()):
                pot_address = alert_event.alert.metadata[key]
                if pot_address is not None and len(pot_address) == 42:
                    pot_attacker_addresses.append(pot_address.lower())
        logging.info(f"alert {alert_event.alert_hash} {alert_event.alert_id} - Analysing {len(pot_attacker_addresses)} pot attacker addresses obtained from labels and metadata")

    except Exception as e:
        logging.warning(f"alert {alert_event.alert_hash} {alert_event.alert_id} - Exception in get_pot_attacker_addresses from labels: {e} {traceback.format_exc()}")

    if len(pot_attacker_addresses) == 0:
        logging.info(f"alert {alert_event.alert_hash} {alert_event.alert_id} - No attack labels in alert. Using addresses field.")
        pot_attacker_addresses = alert_event.alert.addresses
        logging.info(f"alert {alert_event.alert_hash} {alert_event.alert_id} - Analysing {len(pot_attacker_addresses)} pot attacker addresses obtained from addresses field")

    return pot_attacker_addresses

def get_victim_info(alert_data: pd.DataFrame, victims: dict):
    victim_address, victim_name = "", ""
    victim_metadata = dict()

    df_intersection = alert_data[alert_data["transaction_hash"].isin(victims.keys())]

    if(len(df_intersection) > 0):
        tx_hash_with_victim_info = df_intersection.iloc[0]["transaction_hash"]
        victim_metadata = victims[tx_hash_with_victim_info]
        victim_address = victim_metadata["address1"] if "address1" in victim_metadata.keys() else ""
        victim_name = victim_metadata["tag1"] if "tag1" in victim_metadata.keys() else ""

    return victim_address, victim_name, victim_metadata


def get_anomaly_score(alert_event: forta_agent.alert_event.AlertEvent) -> float:
    global DEFAULT_ANOMALY_SCORE

    anomaly_score = 1.0
    if alert_event.alert.metadata is not None and "anomaly_score" in alert_event.alert.metadata.keys():
        anomaly_score_str = alert_event.alert.metadata["anomaly_score"]
    elif alert_event.alert.metadata is not None and "anomalyScore" in alert_event.alert.metadata.keys():
        anomaly_score_str = alert_event.alert.metadata["anomalyScore"]
    else:
        logging.warning(f"alert {alert_event.alert_hash} {alert_event.alert_id} - no anomaly_score in metadata found: {alert_event.alert.metadata}. Treating as anomaly_score of 1.0.")
        anomaly_score_str = "1.0"

    anomaly_score = float(anomaly_score_str)
    if anomaly_score <= 0.0:
        anomaly_score = DEFAULT_ANOMALY_SCORE
        logging.warning(f"alert {alert_event.alert_hash} - anomaly_score is less or equal than 0.0. Treating as anomaly_score of {DEFAULT_ANOMALY_SCORE}.")
    elif anomaly_score > 1.0:
        anomaly_score = 1.0
        logging.warning(f"alert {alert_event.alert_hash} - anomaly_score is greater than 1.0. Treating as anomaly_score of 1.0.")

    return anomaly_score

def is_polygon_validator(w3, cluster: str, tx_hash: str) -> bool:
    if CHAIN_ID == 137:
        tx = w3.eth.get_transaction_receipt(tx_hash)
        for log in tx['logs']:
            if len(log['topics']) > 3:
                if log['topics'][0] == HexBytes('0x4dfe1bbbcf077ddc3e01291eea2d5c70c2b422b415d95645b9adcfd678cb1d63'):  # logfeetransfer event
                    validator = log['topics'][3].hex()[-40:]  # validator in 3rd pos
                    if validator in cluster:
                        return True
    return False

def get_end_user_attack_addresses(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    addresses = set()

    #0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15,HARD-RUG-PULL-1,metadata,,attacker_deployer_address,
    #0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15,HARD-RUG-PULL-1,metadata,,attackerDeployerAddress,
    #0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4,SOFT-RUG-PULL-,metadata,,deployer,
    #0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11,RAKE-TOKEN-CONTRACT-1,metadata,,attackerRakeTokenDeployer,
    #0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11,RAKE-TOKEN-CONTRACT-1,metadata,,attacker_rake_token_deployer,
    #0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127,IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR,eoa,metadata,,newTokenDeployer,
    #0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127,IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR,eoa,metadata,,new_token_deployer,
    #0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1,*,eoa,metadata,,attackerAddress,
    #0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1,*,eoa,metadata,,attacker_address,
    #0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1,*,eoa,metadata,,deployer,
    if alert_event.bot_id == '0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15':  # hard rug pull
        if alert_event.alert.metadata.get('attacker_deployer_address') is not None:
            addresses.add(alert_event.alert.metadata['attacker_deployer_address'].lower())
        if alert_event.alert.metadata.get('attackerDeployerAddress') is not None:
            addresses.add(alert_event.alert.metadata['attacker_deployer_address'].lower())
    elif alert_event.bot_id == '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4':  # soft rug pull
        if alert_event.alert.metadata.get('deployer') is not None:
            addresses.add(alert_event.alert.metadata['deployer'].lower().replace('"', ''))
    elif alert_event.bot_id == '0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11':
        if alert_event.alert.metadata.get('attackerRakeTokenDeployer') is not None:
            addresses.add(alert_event.alert.metadata['attackerRakeTokenDeployer'].lower())
        if alert_event.alert.metadata.get('attacker_rake_token_deployer') is not None:
            addresses.add(alert_event.alert.metadata['attacker_rake_token_deployer'].lower())
    elif alert_event.bot_id == '0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127':
        if alert_event.alert.metadata.get('newTokenDeployer') is not None:
            addresses.add(alert_event.alert.metadata['newTokenDeployer'].lower())
        if alert_event.alert.metadata.get('new_token_deployer') is not None:
            addresses.add(alert_event.alert.metadata['new_token_deployer'].lower())
    elif alert_event.bot_id == '0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1':
        if alert_event.alert.metadata.get('attackerAddress') is not None:
            addresses.add(alert_event.alert.metadata['attackerAddress'].lower().replace('"', ''))
        if alert_event.alert.metadata.get('attacker_address') is not None:
            addresses.add(alert_event.alert.metadata['attacker_address'].lower().replace('"', ''))
        if alert_event.alert.metadata.get('deployer') is not None:
            addresses.add(alert_event.alert.metadata['deployer'].lower().replace('"', ''))

    return list(addresses)


def detect_attack(w3, du, alert_event: forta_agent.alert_event.AlertEvent) -> list:
    """
    this function returns finding for any address with at least 3 alerts observed on that address; it will generate an anomaly score
    :return: findings: list
    """
    global ALERT_ID_STAGE_MAPPING

    global ALERTED_CLUSTERS_LOOSE
    global ALERTED_CLUSTERS_FP_MITIGATED
    global ALERTED_CLUSTERS_STRICT
    global CHAIN_ID
    global HIGHLY_PRECISE_BOTS

    findings = []
    try:
        start = time.time()

        if CHAIN_ID == -1:
            reinitialize()
            if CHAIN_ID == -1:
                logging.error(f"CHAIN_ID not set")
                raise Exception("CHAIN_ID not set")

        chain_id = int(alert_event.chain_id)
        if chain_id == CHAIN_ID or (CHAIN_ID in [10, 42161] and chain_id == 1):
            logging.info(f"alert {alert_event.alert_hash} received for proper chain {chain_id}")

            #  assess whether we generate a finding
            #  note, only one instance will be running at a time to keep up with alert volume
            try:

                # update entity clusters
                if in_list(alert_event, [(ENTITY_CLUSTER_BOT, ENTITY_CLUSTER_BOT_ALERT_ID)]):
                    logging.info(f"alert {alert_event.alert_hash} is entity cluster alert")
                    cluster = alert_event.alert.metadata["entityAddresses"].lower()

                    for address in cluster.split(','):
                        du.put_entity_cluster(dynamo, alert_event.alert.created_at, address, cluster)
                        
                        stored_alert_data_address = du.read_alert_data(dynamo, address)

                        if not stored_alert_data_address.empty:
                            du.delete_alert_data(dynamo, address)
                            stored_alert_data_cluster = du.read_alert_data(dynamo, cluster)
                            if not stored_alert_data_cluster.empty:
                                alert_data_cluster = pd.concat([stored_alert_data_address, stored_alert_data_cluster], ignore_index=True, axis=0)
                            else:
                                alert_data_cluster = stored_alert_data_address
                            du.put_alert_data(dynamo, cluster, alert_data_cluster)
                        
                        if address in du.read_fp_mitigation_clusters(dynamo):
                            du.put_fp_mitigation_cluster(dynamo, cluster)
                        if address in du.read_end_user_attack_clusters(dynamo):
                            du.put_end_user_attack_cluster(dynamo, cluster)

                # update victim alerts
                if (in_list(alert_event, [(VICTIM_IDENTIFICATION_BOT, VICTIM_IDENTIFICATION_BOT_ALERT_IDS[0]),(VICTIM_IDENTIFICATION_BOT, VICTIM_IDENTIFICATION_BOT_ALERT_IDS[1])])):
                    logging.info(f"alert {alert_event.alert_hash} is a victim identification alert")
                    du.put_victim(dynamo, alert_event.alert.source.transaction_hash, alert_event.alert.metadata)

                # update FP mitigation clusters
                if in_list(alert_event, FP_MITIGATION_BOTS):
                    logging.info(f"alert {alert_event.alert_hash} is a FP mitigation alert")
                    address = alert_event.alert.description[0:42]
                    cluster = address
                    entity_clusters = du.read_entity_clusters(dynamo, address)
                    if address in entity_clusters.keys():
                        cluster = entity_clusters[address]
                    du.put_fp_mitigation_cluster(dynamo, cluster.lower())

                # update end user clusters
                if in_list(alert_event, END_USER_ATTACK_BOTS):
                    logging.info(f"alert {alert_event.alert_hash} is an end user alert")
                    addresses = get_end_user_attack_addresses(alert_event)
                    for address in addresses:
                        cluster = address
                        entity_clusters = du.read_entity_clusters(dynamo, address)
                        if address in entity_clusters.keys():
                            cluster = entity_clusters[address]
                        du.put_end_user_attack_cluster(dynamo, cluster.lower())
                        logging.info(f"alert {alert_event.alert_hash} adding end user attacks cluster: {cluster}.")

                # update alerts and process them for a given cluster
                if in_list(alert_event, BASE_BOTS):
                    logging.info(f"alert {alert_event.alert_hash}: is a base bot {alert_event.alert.source.bot.id}, {alert_event.alert_id} alert for addresses {alert_event.alert.addresses}")

                    # analyze attacker addresses from labels if there are any; otherwise analyze all addresses
                    pot_attacker_addresses = get_pot_attacker_addresses(alert_event)


                    for address in pot_attacker_addresses:
                        logging.info(f"alert {alert_event.alert_hash} - Analysing address {address}")
                        address_lower = address.lower()
                        cluster = address_lower
                        entity_clusters = du.read_entity_clusters(dynamo, address_lower)
                        if address_lower in entity_clusters.keys():
                            cluster = entity_clusters[address_lower]
                        if(not Utils.is_address(cluster)):  # ignore contracts and invalid addresses like 0x0000000000000blabla
                            logging.info(f"alert {alert_event.alert_hash}: {cluster} is not an address. Continue ... ")
                            continue

                        logging.info(f"alert {alert_event.alert_hash}: {cluster} is valid EOA.")

                        alert_anomaly_score = get_anomaly_score(alert_event)

                        stage = ALERT_ID_STAGE_MAPPING[(alert_event.bot_id, alert_event.alert.alert_id)]
                        logging.info(f"alert {alert_event.alert_hash} {alert_event.bot_id} {alert_event.alert.alert_id} {stage}: {cluster} anomaly score of {alert_anomaly_score}")

                        stored_alert_data_cluster = du.read_alert_data(dynamo, cluster)
                        if stored_alert_data_cluster.empty:
                            if CHAIN_ID in [10, 42161]:
                                alert_data_cluster = pd.DataFrame(columns=['stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'chain_id', 'addresses', 'transaction_hash'])
                            else:
                                alert_data_cluster = pd.DataFrame(columns=['stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'addresses', 'transaction_hash'])
                        else:
                            alert_data_cluster = stored_alert_data_cluster

                        stage = ALERT_ID_STAGE_MAPPING[(alert_event.bot_id, alert_event.alert.alert_id)]
                        if CHAIN_ID in [10, 42161]:
                            new_alert_data = pd.DataFrame([[stage, datetime.strptime(alert_event.alert.created_at[:-4] + 'Z', "%Y-%m-%dT%H:%M:%S.%fZ"), alert_anomaly_score, alert_event.alert_hash, alert_event.bot_id, alert_event.alert.alert_id, chain_id, alert_event.alert.addresses, alert_event.alert.source.transaction_hash]], columns=['stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'chain_id', 'addresses', 'transaction_hash'])
                        else:
                            new_alert_data = pd.DataFrame([[stage, datetime.strptime(alert_event.alert.created_at[:-4] + 'Z', "%Y-%m-%dT%H:%M:%S.%fZ"), alert_anomaly_score, alert_event.alert_hash, alert_event.bot_id, alert_event.alert.alert_id, alert_event.alert.addresses, alert_event.alert.source.transaction_hash]], columns=['stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'addresses', 'transaction_hash'])
                        alert_data_cluster = pd.concat([alert_data_cluster, new_alert_data], ignore_index=True, axis=0)
                        logging.info(f"alert {alert_event.alert_hash} - alert data size for cluster {cluster} now: {len(alert_data_cluster)}")

                        du.put_alert_data(dynamo, cluster, alert_data_cluster)
                        alert_data = alert_data_cluster
                        
                        # 3. contains highly precise bot
                        highly_precise_bot_alert_id_count = 0
                        highly_precise_bot_ids = set()
                        uniq_bot_alert_ids = alert_data[['bot_id', 'alert_id']].drop_duplicates(inplace=False)
                        for bot_id, alert_id, s in HIGHLY_PRECISE_BOTS:
                            if bot_id == '0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac':  # temp hot fix for FP; awaiting FP mitigation from basebot (https://github.com/NethermindEth/forta-starter-kits/issues/59)
                                highly_precise_bot_alerts = alert_data[(alert_data['bot_id'] == bot_id) & (alert_data['alert_id'] == alert_id)]
                                if len(highly_precise_bot_alerts) > 0 and highly_precise_bot_alerts['anomaly_score'].max() > 0.5:
                                    logging.info(f"Large profit anomaly score not anomalous enough ({highly_precise_bot_alerts['anomaly_score'].max()}) for inclusion in high precision count; skipping ...")
                                    continue

                            if len(uniq_bot_alert_ids[(uniq_bot_alert_ids['bot_id'] == bot_id) & (uniq_bot_alert_ids['alert_id'] == alert_id)]) > 0:
                                highly_precise_bot_alert_id_count += 1
                                highly_precise_bot_ids.add(bot_id)

                        # analyze alert_data to see whether conditions are met to generate a finding
                        # 1. Have to have at least MIN_ALERTS_COUNT bots reporting alerts
                        if len(alert_data['bot_id'].drop_duplicates(inplace=False)) >= MIN_ALERTS_COUNT or highly_precise_bot_alert_id_count>0:
                            # 2. Have to have overall anomaly score of less than ANOMALY_SCORE_THRESHOLD
                            anomaly_scores_by_stages = alert_data[['stage', 'anomaly_score']].drop_duplicates(inplace=False)
                            anomaly_scores = anomaly_scores_by_stages.groupby('stage').min()
                            anomaly_score = anomaly_scores['anomaly_score'].prod()
                            logging.info(f"alert {alert_event.alert_hash} - Have sufficient number of alerts for {cluster}. Overall anomaly score is {anomaly_score}, {len(anomaly_scores)} stages, {highly_precise_bot_alert_id_count} highly precise bot alert ids, {len(highly_precise_bot_ids)} highly precise bot ids.")
                            logging.info(f"alert {alert_event.alert_hash} - {cluster} anomaly scores {anomaly_scores}.")

                            if anomaly_score < ANOMALY_SCORE_THRESHOLD_LOOSE or len(anomaly_scores) == 4 or (highly_precise_bot_alert_id_count>0 and len(anomaly_scores)>1) or (len(highly_precise_bot_ids)>1):
                                logging.info(f"alert {alert_event.alert_hash} - Overall anomaly score for {cluster} is below threshold, 4 stages, or highly precise bot with 2 stages have been observed or two highly precise bots have been observed. Unless FP mitigation kicks in, will raise finding.")
                                if CHAIN_ID in [10, 42161] and alert_data[alert_data['chain_id'] == CHAIN_ID].empty:
                                    logging.info(f"No alert on chain {CHAIN_ID} for {cluster}. Wont raise finding")
                                    continue

                                fp_mitigated = False
                                end_user_attack = False
                                if(Utils.is_contract(w3, cluster)):
                                    logging.info(f"alert {alert_event.alert_hash} - {cluster} is contract. Wont raise finding")
                                    continue

                                etherscan_label = Utils.get_etherscan_label(cluster).lower()
                                if not ('attack' in etherscan_label
                                        or 'phish' in etherscan_label
                                        or 'hack' in etherscan_label
                                        or 'heist' in etherscan_label
                                        or 'exploit' in etherscan_label
                                        or 'scam' in etherscan_label
                                        or 'fraud' in etherscan_label
                                        or etherscan_label == ''):
                                    logging.info(f"alert {alert_event.alert_hash} -  Non attacker etherscan FP mitigation label {etherscan_label} for cluster {cluster}.")
                                    fp_mitigated = True

                                if (CHAIN_ID == 137 and len(alert_data) > POLYGON_VALIDATOR_ALERT_COUNT_THRESHOLD) or is_polygon_validator(w3, cluster, alert_event.alert.source.block.number):
                                    logging.info(f"alert {alert_event.alert_hash} - {cluster} is polygon validator. Wont raise finding")
                                    fp_mitigated = True

                                if cluster in du.read_fp_mitigation_clusters(dynamo):
                                    logging.info(f"alert {alert_event.alert_hash} - Mitigating FP for {cluster}. Wont raise finding")
                                    fp_mitigated = True

                                if cluster in du.read_end_user_attack_clusters(dynamo):
                                    logging.info(
                                        f"alert {alert_event.alert_hash} - End user attack identified for {cluster}. Downgrade finding")
                                    end_user_attack = True

                                if not end_user_attack and not fp_mitigated and (len(anomaly_scores) == 4) and cluster not in ALERTED_CLUSTERS_STRICT:
                                    logging.info(f"alert {alert_event.alert_hash} -1 critical severity finding for {cluster}. Anomaly score is {anomaly_score}.")
                                    victims = du.read_victims(dynamo)
                                    victim_address, victim_name, victim_metadata = get_victim_info(alert_data, victims)
                                    update_list(ALERTED_CLUSTERS_STRICT, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, cluster)
                                    findings.append(AlertCombinerFinding.create_finding(block_chain_indexer, cluster, victim_address, victim_name, anomaly_score, FindingSeverity.Critical, "ATTACK-DETECTOR-1", alert_event, alert_data, victim_metadata, anomaly_scores_by_stages, CHAIN_ID))
                                elif not end_user_attack and not fp_mitigated and ((highly_precise_bot_alert_id_count > 0 and len(anomaly_scores) > 1) or (len(highly_precise_bot_ids)>1)) and cluster not in ALERTED_CLUSTERS_STRICT:
                                    logging.info(f"alert {alert_event.alert_hash} -1 critical severity finding for {cluster}. Anomaly score is {anomaly_score}.")
                                    victims = du.read_victims(dynamo)
                                    victim_address, victim_name, victim_metadata = get_victim_info(alert_data, victims)
                                    update_list(ALERTED_CLUSTERS_STRICT, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, cluster)
                                    findings.append(AlertCombinerFinding.create_finding(block_chain_indexer, cluster, victim_address, victim_name, anomaly_score, FindingSeverity.Critical, "ATTACK-DETECTOR-2", alert_event, alert_data, victim_metadata, anomaly_scores_by_stages, CHAIN_ID))
                                elif not end_user_attack and not fp_mitigated and (len(alert_data['bot_id'].drop_duplicates(inplace=False)) >= MIN_ALERTS_COUNT and anomaly_score < ANOMALY_SCORE_THRESHOLD_STRICT) and cluster not in ALERTED_CLUSTERS_STRICT:
                                    logging.info(f"alert {alert_event.alert_hash} -1 critical severity finding for {cluster}. Anomaly score is {anomaly_score}.") 
                                    victims = du.read_victims(dynamo)
                                    victim_address, victim_name, victim_metadata = get_victim_info(alert_data, victims)
                                    update_list(ALERTED_CLUSTERS_STRICT, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, cluster)
                                    findings.append(AlertCombinerFinding.create_finding(block_chain_indexer, cluster, victim_address, victim_name, anomaly_score, FindingSeverity.Critical, "ATTACK-DETECTOR-3", alert_event, alert_data, victim_metadata, anomaly_scores_by_stages, CHAIN_ID))
                                elif not end_user_attack and not fp_mitigated and (len(alert_data['bot_id'].drop_duplicates(inplace=False)) >= MIN_ALERTS_COUNT  and anomaly_score < ANOMALY_SCORE_THRESHOLD_LOOSE) and cluster not in ALERTED_CLUSTERS_LOOSE and cluster not in ALERTED_CLUSTERS_STRICT:
                                    logging.info(f"alert {alert_event.alert_hash} -1 low severity finding for {cluster}. Anomaly score is {anomaly_score}.") 
                                    victims = du.read_victims(dynamo)
                                    victim_address, victim_name, victim_metadata = get_victim_info(alert_data, victims)
                                    update_list(ALERTED_CLUSTERS_LOOSE, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, cluster)
                                    findings.append(AlertCombinerFinding.create_finding(block_chain_indexer, cluster, victim_address, victim_name, anomaly_score, FindingSeverity.Low, "ATTACK-DETECTOR-4", alert_event, alert_data, victim_metadata, anomaly_scores_by_stages, CHAIN_ID))
                                elif not end_user_attack and fp_mitigated and (cluster not in ALERTED_CLUSTERS_FP_MITIGATED) and (((len(anomaly_scores) == 4) and cluster not in ALERTED_CLUSTERS_STRICT) or ((highly_precise_bot_alert_id_count > 0 and len(anomaly_scores) > 1) and cluster not in ALERTED_CLUSTERS_STRICT) or (len(highly_precise_bot_ids)>1) or ((len(alert_data['bot_id'].drop_duplicates(inplace=False)) >= MIN_ALERTS_COUNT and anomaly_score < ANOMALY_SCORE_THRESHOLD_STRICT) and cluster not in ALERTED_CLUSTERS_STRICT)
                                                                                         or ((len(alert_data['bot_id'].drop_duplicates(inplace=False)) >= MIN_ALERTS_COUNT  and anomaly_score < ANOMALY_SCORE_THRESHOLD_LOOSE) and cluster not in ALERTED_CLUSTERS_LOOSE and cluster not in ALERTED_CLUSTERS_STRICT)):
                                    victims = du.read_victims(dynamo)
                                    victim_address, victim_name, victim_metadata = get_victim_info(alert_data, victims)
                                    update_list(ALERTED_CLUSTERS_FP_MITIGATED, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, cluster)
                                    findings.append(AlertCombinerFinding.create_finding(block_chain_indexer, cluster, victim_address, victim_name, anomaly_score, FindingSeverity.Info, "ATTACK-DETECTOR-5", alert_event, alert_data, victim_metadata, anomaly_scores_by_stages, CHAIN_ID))
                                elif end_user_attack and not fp_mitigated and (cluster not in ALERTED_CLUSTERS_FP_MITIGATED) and (((len(anomaly_scores) == 4) and cluster not in ALERTED_CLUSTERS_STRICT) or ((highly_precise_bot_alert_id_count > 0 and len(anomaly_scores) > 1) and cluster not in ALERTED_CLUSTERS_STRICT) or (len(highly_precise_bot_ids)>1) or ((len(alert_data['bot_id'].drop_duplicates(inplace=False)) >= MIN_ALERTS_COUNT and anomaly_score < ANOMALY_SCORE_THRESHOLD_STRICT) and cluster not in ALERTED_CLUSTERS_STRICT)
                                                                                         or ((len(alert_data['bot_id'].drop_duplicates(inplace=False)) >= MIN_ALERTS_COUNT  and anomaly_score < ANOMALY_SCORE_THRESHOLD_LOOSE) and cluster not in ALERTED_CLUSTERS_LOOSE and cluster not in ALERTED_CLUSTERS_STRICT)):
                                    victims = du.read_victims(dynamo)
                                    victim_address, victim_name, victim_metadata = get_victim_info(alert_data, victims)
                                    update_list(ALERTED_CLUSTERS_FP_MITIGATED, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, cluster)
                                    findings.append(AlertCombinerFinding.create_finding(block_chain_indexer, cluster, victim_address, victim_name, anomaly_score, FindingSeverity.Info, "ATTACK-DETECTOR-6", alert_event, alert_data, victim_metadata, anomaly_scores_by_stages, CHAIN_ID))
                                else:
                                    logging.info(f"alert {alert_event.alert_hash} - Not raising finding for {cluster}. Already alerted.")

            except Exception as e:
                logging.warning(f"alert {alert_event.alert_hash} - Exception in process_alert {alert_event.alert_hash}: {e} {traceback.format_exc()}")
        else:
            logging.debug(f"alert {alert_event.alert_hash} received for incorrect chain {alert_event.chain_id}. This bot is for chain {CHAIN_ID}.")
            raise AssertionError(f"alert {alert_event.alert_hash} received for incorrect chain {alert_event.chain_id}. This bot is for chain {CHAIN_ID}.")

        end = time.time()
        logging.info(f"alert {alert_event.alert_hash} {alert_event.alert_id} {alert_event.chain_id} processing took {end - start} seconds")
    except Exception as e:
        logging.warning(f"alert {alert_event.alert_hash} - Exception in process_alert {alert_event.alert_hash}: {e} {traceback.format_exc()}")
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"alert {alert_event.alert_hash} - Raising exception to expose error to scannode")
            raise e

    return findings


def update_list(items: list, max_size: int, item: str):

    items.append(item.lower())

    while len(items) > max_size:
        items.pop(0)  # remove oldest item


def in_list(alert_event: forta_agent.alert_event.AlertEvent, bots: list) -> bool:
    """
    this function returns True if the alert is from a bot in the bots tuple
    :return: bool
    """
    for item in bots:
        if type(item) is tuple:
            if alert_event.alert.source.bot.id == item[0] and alert_event.alert.alert_id == item[1]:
                return True
        else:
            if alert_event.alert.source.bot.id == item:
                return True

    return False


def persist_state():
    global ALERTED_CLUSTERS_STRICT_KEY
    global ALERTED_CLUSTERS_STRICT
    global ALERTED_CLUSTERS_LOOSE_KEY
    global ALERTED_CLUSTERS_LOOSE
    global ALERTED_CLUSTERS_FP_MITIGATED_KEY
    global ALERTED_CLUSTERS_FP_MITIGATED
    global CHAIN_ID

    start = time.time()
    persist(ALERTED_CLUSTERS_LOOSE, CHAIN_ID, ALERTED_CLUSTERS_LOOSE_KEY)
    persist(ALERTED_CLUSTERS_FP_MITIGATED, CHAIN_ID, ALERTED_CLUSTERS_FP_MITIGATED_KEY)
    persist(ALERTED_CLUSTERS_STRICT, CHAIN_ID, ALERTED_CLUSTERS_STRICT_KEY)
    end = time.time()
    logging.info(f"Persisted bot state. took {end - start} seconds")


def persist(obj: object, chain_id: int, key: str):
    L2Cache.write(obj, chain_id, key)


def load(chain_id: int, key: str) -> object:
    return L2Cache.load(chain_id, key)


def provide_handle_alert(w3, du):
    logging.debug("provide_handle_alert called")

    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        logging.debug("handle_alert inner called")
        global INITIALIZED
        if not INITIALIZED:
            raise Exception("Not initialized")

        findings = detect_attack(w3, du, alert_event)
        if not ('NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV')):
            persist_state()

        return findings

    return handle_alert


real_handle_alert = provide_handle_alert(web3, DynamoUtils(web3.eth.chain_id))

def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    logging.debug("handle_alert called")
    return real_handle_alert(alert_event)

def handle_block(block_event: forta_agent.BlockEvent):
    logging.debug("handle_block called")

    if datetime.now().minute == 0:  # every hour
        persist_state()

    return []
