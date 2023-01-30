import logging
import sys
import threading
from datetime import datetime, timedelta
from xmlrpc.client import _datetime

import forta_agent
import pandas as pd
import re
import os
import pickle
import requests
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3

from src.constants import (ADDRESS_QUEUE_SIZE, BASE_BOTS, ENTITY_CLUSTER_BOT_ALERT_ID,
                           DATE_LOOKBACK_WINDOW_IN_DAYS, TX_COUNT_FILTER_THRESHOLD,
                           ENTITY_CLUSTER_BOT, ENTITY_CLUSTER_BOT_DATE_LOOKBACK_WINDOW_IN_DAYS,
                           FP_MITIGATION_ADDRESSES, FINDINGS_CACHE_KEY, ALERTED_CLUSTERS_KEY)
from src.findings import AlertCombinerFinding
from src.forta_explorer import FortaExplorer

label_api = "https://api.forta.network/labels/state?sourceIds=etherscan&entities="

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
forta_explorer = FortaExplorer()

DATABASE = "https://research.forta.network/database/bot/"

FINDINGS_CACHE = []
ALERTED_CLUSTERS = []
MUTEX = False
ICE_PHISHING_MAPPINGS_DF = pd.DataFrame()

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
    global ALERTED_CLUSTERS
    alerted_clusters = load(ALERTED_CLUSTERS_KEY)
    ALERTED_CLUSTERS = [] if alerted_clusters is None else alerted_clusters
    logging.info(f"Loaded {len(ALERTED_CLUSTERS)} alerted clusters from cache")
    if len(ALERTED_CLUSTERS) < 100:
        logging.info(f"Loaded {ALERTED_CLUSTERS} alerted clusters from cache")

    
    global FINDINGS_CACHE
    FINDINGS_CACHE = [] 

    global MUTEX
    MUTEX = False

    global ICE_PHISHING_MAPPINGS_DF
    ICE_PHISHING_MAPPINGS_DF = pd.read_csv('ice_phishing_mappings.csv')


def get_etherscan_label(address: str):
    try:
        res = requests.get(label_api + address.lower())
        if res.status_code == 200:
            labels = res.json()
            if len(labels) > 0:
                return labels['events'][0]['label']['label']
    except Exception as e:
        logging.error(f"Exception in get_etherscan_label {e}")
        return ""
        

def handle_alert(alert_event):
    print("handle_alert")
    print(alert_event)

def is_contract(w3, addresses) -> bool:
    """
    this function determines whether address/ addresses is a contract; if all are contracts, returns true; otherwise false
    :return: is_contract: bool
    """
    if addresses is None:
        return True

    is_contract = True
    for address in addresses.split(','):
        try:
            code = w3.eth.get_code(Web3.toChecksumAddress(address))
        except: # Exception as e:
            logging.error("Exception in is_contract")

        is_contract = is_contract & (code != HexBytes('0x'))

    return is_contract

def is_address(w3, addresses: str) -> bool:
    """
    this function determines whether address is a valid address
    :return: is_address: bool
    """
    if addresses is None:
        return True

    is_address = True
    for address in addresses.split(','):
        for c in ['a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
            test_str = c + c + c + c + c + c + c + c + c  # make a string of length 9; I know this is ugly, but regex didnt work
            if test_str in address.lower():
                is_address = False

    return is_address

def replace_with_cluster_identifiers(addresses: list, clusters: list) -> list:
    cluster_identifiers = []

    for address in addresses:
        address_lower = address.lower()
        found = False
        for cluster in clusters:
            cluster_lower = cluster.lower()
            if address_lower in cluster_lower:
                found = True
                cluster_identifiers.append(cluster_lower)
                break
        if not found:
            cluster_identifiers.append(address_lower)

    return cluster_identifiers

def get_max_transaction_count(w3, cluster: str) -> int:
    max_transaction_count = 0
    for address in cluster.split(','):
        transaction_count = w3.eth.get_transaction_count(Web3.toChecksumAddress(address))
        if transaction_count > max_transaction_count:
            max_transaction_count = transaction_count
    return max_transaction_count


def get_clusters_exploded(start_date: datetime, end_date: datetime, forta_explorer: FortaExplorer, chain_id: int) -> pd.DataFrame:
    df_address_clusters_alerts = forta_explorer.alerts_by_bot(ENTITY_CLUSTER_BOT, ENTITY_CLUSTER_BOT_ALERT_ID, chain_id, start_date, end_date)  #  metadate entity_addresses: "address1, address2, address3" (web3 checksum)
    logging.info(f"Fetched {len(df_address_clusters_alerts)} for entity clusters")

    df_address_clusters = pd.DataFrame()
    df_address_clusters["entity_addresses"] = df_address_clusters_alerts["metadata"].apply(lambda x: x["entityAddresses"].lower())
    df_address_clusters["entity_addresses_arr"] = df_address_clusters_alerts["metadata"].apply(lambda x: x["entityAddresses"].lower().split(","))
    df_address_clusters = df_address_clusters.explode("entity_addresses_arr")
    df_address_clusters["addresses"] = df_address_clusters["entity_addresses_arr"].apply(lambda x: x.lower())
    df_address_clusters = df_address_clusters.set_index("addresses")

    return df_address_clusters


def get_forta_alerts(start_date: datetime, end_date: datetime, df_address_clusters: pd.DataFrame, forta_explorer: FortaExplorer, chain_id: int) -> pd.DataFrame:
    logging.info(f"Analyzing alerts from {start_date} to {end_date}, chain_id: {chain_id}")

    # get all alerts for date range
    df_forta_alerts = forta_explorer.empty_alerts()
    for bot_id, alert_id, stage in BASE_BOTS:
        bot_alerts = forta_explorer.alerts_by_bot(bot_id, alert_id, chain_id, start_date, end_date)
        df_forta_alerts = pd.concat([df_forta_alerts, bot_alerts])
        if len(bot_alerts) > 0:
            logging.info(f"Fetched {len(bot_alerts)} for bot {bot_id}, alert_id {alert_id}, chain_id {chain_id}")

    # add a new field cluster_identifiers where all addresses are replaced with cluster identifiers if they exist
    df_forta_alerts.drop(columns=["createdAt", "name", "protocol", "findingType", "source", "contracts"], inplace=True)
    df_forta_alerts_exploded = df_forta_alerts.explode("addresses")
    df_forta_alerts_exploded["addresses"] = df_forta_alerts_exploded["addresses"].apply(lambda x: x.lower())
    df_forta_alerts_exploded = df_forta_alerts_exploded.set_index("addresses")

    df_forta_alerts_clusters_joined = df_forta_alerts_exploded.join(df_address_clusters, on="addresses", how="left", lsuffix="_alert", rsuffix="_cluster")
    df_forta_alerts_clusters_joined = df_forta_alerts_clusters_joined.reset_index()
    df_forta_alerts_clusters_joined["cluster_identifiers"] = df_forta_alerts_clusters_joined.apply(lambda x: x["addresses"] if pd.isnull(x["entity_addresses"]) else x["entity_addresses"], axis=1)
    df_forta_alerts_clusters_joined.drop(columns=["entity_addresses_arr", "entity_addresses"], inplace=True)

    df_forta_alerts = df_forta_alerts_clusters_joined.groupby(['hash']).agg({"cluster_identifiers": lambda x: x.tolist(), "severity": "first", "alertId": "first", "bot_id": "first", "description": "first", "metadata": "first", "transactionHash": "first"})
    df_forta_alerts.reset_index(inplace=True)
    logging.info("Added cluster identifiers to alerts")

    return df_forta_alerts


def swap_addresses_with_clusters(addresses: list, df_address_clusters_exploded: pd.DataFrame) -> list:
    df_addresses = pd.DataFrame(addresses, columns=["addresses"])
    df_addresses["addresses"] = df_addresses["addresses"].apply(lambda x: x.lower())

    df_addresses_joined = df_addresses.join(df_address_clusters_exploded, on="addresses", how="left", lsuffix="_alert", rsuffix="_cluster")
    df_addresses_joined = df_addresses_joined.reset_index()
    if len(df_addresses_joined) > 0:
        df_addresses_joined["cluster_identifiers"] = df_addresses_joined.apply(lambda x: x["addresses"] if pd.isnull(x["entity_addresses"]) else x["entity_addresses"], axis=1)
        df_addresses_joined.drop(columns=["entity_addresses_arr", "entity_addresses"], inplace=True)

        return df_addresses_joined["cluster_identifiers"].tolist()
    else:
        return []


def detect_attack(w3, forta_explorer: FortaExplorer, block_event: forta_agent.block_event.BlockEvent):
    """
    this function returns finding for any address for which alerts in 4 stages were observed in a given time window
    :return: findings: list
    """
    global ALERTED_CLUSTERS
    global MUTEX

    if not MUTEX:
        MUTEX = True

        ALERT_ID_STAGE_MAPPING = dict([(alert_id, stage) for bot_id, alert_id, stage in BASE_BOTS])

        # get alerts from API and exchange addresses with clusters from the entity cluster bot
        end_date = datetime.utcfromtimestamp(block_event.block.timestamp)
        start_date = end_date - timedelta(days=ENTITY_CLUSTER_BOT_DATE_LOOKBACK_WINDOW_IN_DAYS)
        df_address_clusters_exploded = get_clusters_exploded(start_date=start_date, end_date=end_date, forta_explorer=forta_explorer, chain_id=w3.eth.chain_id)
        logging.info(f"Fetched clusters {len(df_address_clusters_exploded)}")

        end_date = datetime.utcfromtimestamp(block_event.block.timestamp)
        start_date = end_date - timedelta(days=DATE_LOOKBACK_WINDOW_IN_DAYS)
        df_forta_alerts = get_forta_alerts(start_date=start_date, end_date=end_date, df_address_clusters=df_address_clusters_exploded, forta_explorer=forta_explorer, chain_id=w3.eth.chain_id)

        # alert combiner 3 alert - ice phishing
        logging.info("Scam detector - ice phishing")

        ice_phishing = df_forta_alerts[(df_forta_alerts["alertId"] == "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS") | (df_forta_alerts["alertId"] == "ICE-PHISHING-PERMITTED-ERC20-TRANSFER")
                                       | (df_forta_alerts["alertId"] == "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS") | (df_forta_alerts["alertId"] == "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS") | (df_forta_alerts["alertId"] == "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL")
                                       | (df_forta_alerts["alertId"] == "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL") | (df_forta_alerts["alertId"] == "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL")]
        addresses = set()
        ice_phishing["description"].apply(lambda x: addresses.add(get_ice_phishing_attacker_address(x)))
        logging.info(f"Got {len(addresses)} ice phishing addresses")

        clusters = swap_addresses_with_clusters(list(addresses), df_address_clusters_exploded)
        logging.info(f"Mapped ice phishing addresses to {len(clusters)} clusters.")

        for potential_attacker_cluster_lower in clusters:
            try:
                logging.debug(potential_attacker_cluster_lower)
                if "0x000000000000000000000000000" in potential_attacker_cluster_lower:
                    continue

                alert_ids = set()
                involved_clusters = set()
                hashes = set()
                if(len(df_forta_alerts) > 0):
                    cluster_alerts = df_forta_alerts[df_forta_alerts["cluster_identifiers"].apply(lambda x: potential_attacker_cluster_lower in x if x is not None else False)]
                    cluster_alerts = cluster_alerts[cluster_alerts.apply(lambda x: contains_attacker_addresses_ice_phishing(w3, x, potential_attacker_cluster_lower), axis=1)]
                    involved_alert_ids = cluster_alerts["alertId"].unique()
                    for alert_id in involved_alert_ids:
                        if alert_id in ALERT_ID_STAGE_MAPPING.keys():
                            stage = ALERT_ID_STAGE_MAPPING[alert_id]
                            alert_ids.add(alert_id)
                            # get addresses from address field to add to involved_addresses
                            cluster_alerts[cluster_alerts["alertId"] == alert_id]["cluster_identifiers"].apply(lambda x: involved_clusters.update(set(x)))
                            cluster_alerts[cluster_alerts["alertId"] == alert_id]["hash"].apply(lambda x: hashes.add(x))
                            logging.info(f"Found alert {alert_id} in stage {stage} for cluster {potential_attacker_cluster_lower}")

                    logging.info(f"Cluster {potential_attacker_cluster_lower} stages: {alert_ids}")

                    if potential_attacker_cluster_lower not in ALERTED_CLUSTERS:
                        if (('SLEEPMINT-1' in alert_ids or 'SLEEPMINT-2' in alert_ids)
                            or ('MALICIOUS-ACCOUNT-FUNDING' in alert_ids or 'UMBRA-RECEIVE' in alert_ids or 'CEX-FUNDING-1' in alert_ids or 'AK-AZTEC-PROTOCOL-FUNDING' in alert_ids or 'FUNDING-TORNADO-CASH' in alert_ids or 'TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION' in alert_ids or 'POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH' in alert_ids or 'MALICIOUS-ACCOUNT-FUNDING' in alert_ids)
                            or ('UNVERIFIED-CODE-CONTRACT-CREATION' in alert_ids or 'FLASHBOT-TRANSACTION' in alert_ids)
                            or ('AE-MALICIOUS-ADDR' in alert_ids or 'forta-text-messages-possible-hack' in alert_ids)
                            or ('ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS' in alert_ids)):
                            tx_count = 0
                            try:
                                tx_count = get_max_transaction_count(w3, potential_attacker_cluster_lower)
                            except  Exception as e:
                                logging.error(f"Exception in assessing get_transaction_count for cluster {potential_attacker_cluster_lower}: {e}")
                                continue
                        
                            if tx_count > TX_COUNT_FILTER_THRESHOLD:
                                logging.info(f"Cluster {potential_attacker_cluster_lower} transacton count: {tx_count}")
                                continue

                            if potential_attacker_cluster_lower in FP_MITIGATION_ADDRESSES:
                                logging.info(f"Cluster {potential_attacker_cluster_lower} in FP mitigation list")
                                continue

                            etherscan_label = get_etherscan_label(potential_attacker_cluster_lower).lower()
                            if not ('attack' in etherscan_label
                                    or 'phish' in etherscan_label
                                    or 'hack' in etherscan_label
                                    or 'heist' in etherscan_label
                                    or 'scam' in etherscan_label
                                    or 'fraud' in etherscan_label
                                    or etherscan_label == ''):
                                logging.info(f"Cluster {potential_attacker_cluster_lower} has etherscan label {etherscan_label}")
                                continue

                            update_alerted_clusters(w3, potential_attacker_cluster_lower)
                            FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(potential_attacker_cluster_lower, start_date, end_date, involved_clusters, involved_alert_ids, 'ATTACK-DETECTOR-ICE-PHISHING', hashes))
                            logging.info(f"Findings count {len(FINDINGS_CACHE)}")
                    else: 
                        logging.info(f"Cluster {potential_attacker_cluster_lower} already alerted on.")
            except Exception as e:
                logging.warn(f"Error processing address combiner alert 1 {potential_attacker_cluster_lower}: {e}")
                #logging.warn(f"Error processing address combiner alert 3 {potential_attacker_cluster_lower}")
                continue

        MUTEX = False


def get_ice_phishing_attacker_address(description: str) -> str:
    # 0x7DA4580bF3168A78f5e30d9bb82f7Ce46daB2dE7 obtained transfer approval for 3 assets by 6 accounts over period of 2 days. ICE-PHISHING-HIGH-NUM-APPROVALS
    # 0x2f993D27649d935cCcD44E6591eee3f7175866cf obtained transfer approval for all tokens from 0xf45CFeaf03BD53C8e5Ff5524a58d974126284c67. ICE-PHISHING-APPROVAL-FOR-ALL
    # 0x0899935fe73759DCBd7CCd18982980A0733A01Aa transferred 3 assets from 1 accounts over period of 1 days. ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS
    return description[:42].lower()


def contains_attacker_addresses_ice_phishing(w3, alert: pd.Series, potential_attacker_address: str) -> bool:
    global ICE_PHISHING_MAPPINGS_DF
    # iterate over ice phishing mappings and assess whether the potential attacker address is involved according to the mapping
    if "ICE-PHISHING" in alert["alertId"]:
        return True

    for index, row in ICE_PHISHING_MAPPINGS_DF.iterrows():
        #  bot_id,alert_id,location,attacker_address_location_in_description,metadata_field
        if row['bot_id'] == alert['bot_id'] and row['alert_id'] == alert['alertId']:
            if row['location'] == 'description':
                if alert['description'][int(row["attacker_address_location_in_description"]):42].lower() in potential_attacker_address:
                    return True
            elif row['location'] == 'metadata':
                if row['metadata_field'] in alert['metadata'].keys():
                    metadata = alert['metadata'][row["metadata_field"]]
                    for address in re.findall(r"0x[a-fA-F0-9]{40}", metadata):
                        if address in potential_attacker_address:
                            return True
            elif row['location'] == 'cluster_identifiers':
                if potential_attacker_address in alert['cluster_identifiers']:  # lower not required as it comes from the network as opposed to user field
                    return True
            elif row['location'] == 'tx_to':
                if w3.eth.get_transaction(alert['transactionHash'])['to'].lower() in potential_attacker_address:
                    return True

    return False


def update_alerted_clusters(w3, cluster: str):
    """
    this function maintains a list clusters; holds up to CLUSTER_QUEUE_SIZE in memory
    :return: None
    """
    global ALERTED_CLUSTERS

    ALERTED_CLUSTERS.append(cluster.lower())
    logging.info(f"Added {cluster.lower()} to alerted clusters.")
    logging.info(f"ALERTED_CLUSTERS size {len(ALERTED_CLUSTERS)}.")
    if len(ALERTED_CLUSTERS) > ADDRESS_QUEUE_SIZE:
        ALERTED_CLUSTERS.pop(0)


def persist(obj: object, key: str):
    try:
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"Persisting {key} using API")
            bytes = pickle.dumps(obj)
            token = forta_agent.fetch_jwt({})

            headers = {"Authorization": f"Bearer {token}"}
            res = requests.post(f"{DATABASE}{key}", data=bytes, headers=headers)
            logging.info(f"Persisting {key} to database. Response: {res}")
            return
        else:
            logging.info(f"Persisting {key} locally")
            pickle.dump(obj, open(key, "wb"))
    except Exception as e:
        logging.warn(f"Error persisting {key}: {e}")

def load(key: str) -> object:
    try:
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            logging.info(f"Loading {key} using API")
            token = forta_agent.fetch_jwt({})
            headers = {"Authorization": f"Bearer {token}"}
            res = requests.get(f"{DATABASE}{key}", headers=headers)
            logging.info(f"Loaded {key}. Response: {res}")
            if res.status_code==200 and len(res.content) > 0:
                return pickle.loads(res.content)
            else:
                logging.info(f"{key} does not exist")
        else:
            # load locally
            logging.info(f"Loading {key} locally")
            if os.path.exists(key):
                return pickle.load(open(key, "rb"))
            else:
                logging.info(f"File {key} does not exist")
        return None
    except Exception as e:
        logging.warn(f"Error loading {key}: {e}")
        return None

def persist_state():
    global ALERTED_CLUSTERS
    logging.info(f"Persisting alert clusters of length {len(ALERTED_CLUSTERS)}.")
    if len(ALERTED_CLUSTERS) < 100:
        logging.info(f"Persist {ALERTED_CLUSTERS} alerted clusters from cache")
    persist(ALERTED_CLUSTERS, ALERTED_CLUSTERS_KEY)
    logging.info("Persisted bot state.")


def provide_handle_block(w3, forta_explorer):
    logging.debug("provide_handle_block called")

    def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        logging.debug("handle_block with w3 called")
        global FINDINGS_CACHE
        global MUTEX

        findings = FINDINGS_CACHE
        FINDINGS_CACHE = []

        if block_event.block_number % 240 == 0:
            logging.info(f"Persisting block {block_event.block_number}.")
            persist_state()

        #detect_attack(w3, forta_explorer, block_event)
        if not MUTEX:
            thread = threading.Thread(target=detect_attack, args=(w3, forta_explorer, block_event))
            thread.start()

        # uncomment for local testing of tx/block ranges (ok for npm run start); otherwise the process will exit
        #while (thread.is_alive()):
        #    pass
        
        return findings

    return handle_block


real_handle_block = provide_handle_block(web3, forta_explorer)


def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)
