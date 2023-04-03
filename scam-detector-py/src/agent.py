import logging
import sys
import threading
from datetime import datetime, timedelta
from xmlrpc.client import _datetime

import forta_agent
import pandas as pd
import re
import os
import io
import pickle
import requests
import traceback
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3

from src.constants import (ADDRESS_QUEUE_SIZE, BASE_BOTS, ENTITY_CLUSTER_BOT_ALERT_ID,
                           DATE_LOOKBACK_WINDOW_IN_DAYS, TX_COUNT_FILTER_THRESHOLD,
                           ENTITY_CLUSTER_BOT, ENTITY_CLUSTER_BOT_DATE_LOOKBACK_WINDOW_IN_DAYS,
                           ALERTED_CLUSTERS_KEY, ALERTED_FP_ADDRESSES_KEY)
from src.findings import AlertCombinerFinding
from src.forta_explorer import FortaExplorer
from src.blockchain_indexer_service import BlockChainIndexer

label_api = "https://api.forta.network/labels/state?sourceIds=etherscan,0x6f022d4a65f397dffd059e269e1c2b5004d822f905674dbf518d968f744c2ede&entities="

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
block_chain_indexer = BlockChainIndexer()
forta_explorer = FortaExplorer()

DATABASE = f"https://research.forta.network/database/bot/{web3.eth.chain_id}"

CHAIN_ID = -1

FINDINGS_CACHE = []
ALERTED_CLUSTERS = []
ALERTED_FP_ADDRESSES = []
MUTEX = False
ICE_PHISHING_MAPPINGS_DF = pd.DataFrame()
FP_MITIGATION_ADDRESSES = set()

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
    global CHAIN_ID
    try:
        CHAIN_ID = web3.eth.chain_id
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e

    global ALERTED_CLUSTERS
    alerted_clusters = load(ALERTED_CLUSTERS_KEY)
    ALERTED_CLUSTERS = [] if alerted_clusters is None else alerted_clusters
    logging.info(f"Loaded {len(ALERTED_CLUSTERS)} alerted clusters from cache")
    if len(ALERTED_CLUSTERS) < 100:
        logging.info(f"Loaded {ALERTED_CLUSTERS} alerted clusters from cache")

    global ALERTED_FP_ADDRESSES
    alerted_fp_addresses = load(ALERTED_FP_ADDRESSES_KEY)
    ALERTED_FP_ADDRESSES = [] if alerted_fp_addresses is None else alerted_fp_addresses
    logging.info(f"Loaded {len(ALERTED_FP_ADDRESSES)} alerted FP addresses from cache")
    if len(ALERTED_FP_ADDRESSES) < 100:
        logging.info(f"Loaded {ALERTED_FP_ADDRESSES} alerted FP addresses from cache")

    # read addresses from fp_list.txt
    global FP_MITIGATION_ADDRESSES
    content = open('fp_list.csv', 'r').read()
    df_fp = pd.read_csv(io.StringIO(content))
    for index, row in df_fp.iterrows():
        FP_MITIGATION_ADDRESSES.add(row['address'].lower())

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
        logging.warning(f"Exception in get_etherscan_label {e}")
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


def get_sleep_minting_addresses(description: str) -> str:
    # An NFT Transfer was initiated by 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to transfer an NFT owned by 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. It had been previously minted by the 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. The NFT contract address is 0xd57474e76c9ebecc01b65a1494f0a1211df7bcd8
    loc = len("An NFT Transfer was initiated by ")
    return description[loc:loc+42]


def get_wash_trading_addresses(metadata: dict) -> set:
    
    addresses = set()
    if "buyerWallet" in metadata:
        addresses.add(metadata["buyerWallet"].lower())
    if "sellerWallet" in metadata:
        addresses.add(metadata["sellerWallet"].lower())
    logging.info(f"Found {len(addresses)} addresses in wash trading metadata")
    return addresses


def get_address_poisoning_addresses(metadata: dict) -> set:
    print(f"address poisoning metadata: {metadata}")
    addresses = set()
    if "phishingEoa" in metadata:
        addresses.add(metadata["phishingEoa"].lower())
    if "phishingContract" in metadata:
        addresses.add(metadata["phishingContract"].lower())
    if "attackerAddresses" in metadata:
        attacker_addresses = metadata["attackerAddresses"]
        for attacker_address in attacker_addresses.split(","):
            addresses.add(attacker_address.lower())
    logging.info(f"Found {len(addresses)} addresses in address poisoning metadata")
    return addresses


def get_native_ice_phishing_address(metadata: dict) -> str:
    if "attacker" in metadata:
        return metadata["attacker"]
    return ""


def get_seaport_order_attacker_address(metadata: dict) -> str:
    if "toAddr" in metadata:
        return metadata["toAddr"]
    if "initiator" in metadata:
        return metadata["initiator"]
    return ""


def detect_attack(w3, forta_explorer: FortaExplorer, block_event: forta_agent.block_event.BlockEvent):
    """
    this function returns finding for any address for which alerts in 4 stages were observed in a given time window
    :return: findings: list
    """
    global ALERTED_CLUSTERS
    global MUTEX
    global FINDINGS_CACHE
    global FP_MITIGATION_ADDRESSES
    global CHAIN_ID

    if CHAIN_ID == -1:
        logging.error("Chain ID not set")
        return

    if not MUTEX:
        MUTEX = True

        ALERT_ID_STAGE_MAPPING = dict([(alert_id, stage) for bot_id, alert_id, stage in BASE_BOTS])

        # get alerts from API and exchange addresses with clusters from the entity cluster bot
        end_date = datetime.utcfromtimestamp(block_event.block.timestamp)
        start_date = end_date - timedelta(days=ENTITY_CLUSTER_BOT_DATE_LOOKBACK_WINDOW_IN_DAYS)
        df_address_clusters_exploded = get_clusters_exploded(start_date=start_date, end_date=end_date, forta_explorer=forta_explorer, chain_id=CHAIN_ID)
        logging.info(f"Fetched clusters {len(df_address_clusters_exploded)}")

        end_date = datetime.utcfromtimestamp(block_event.block.timestamp)
        start_date = end_date - timedelta(days=DATE_LOOKBACK_WINDOW_IN_DAYS)
        df_forta_alerts = get_forta_alerts(start_date=start_date, end_date=end_date, df_address_clusters=df_address_clusters_exploded, forta_explorer=forta_explorer, chain_id=CHAIN_ID)

        # alert combiner 3 alert - ice phishing
        logging.info("Scam detector - ice phishing/ fraudulent seaport orders")

        native_ice_phishing_addresses = set()
        native_ice_phishing = df_forta_alerts[(df_forta_alerts["alertId"] == "NIP-1")]
        native_ice_phishing["metadata"].apply(lambda x: native_ice_phishing_addresses.add(get_native_ice_phishing_address(x)))
        logging.info(f"Got {len(native_ice_phishing_addresses)} native ice phishing addresses")

        wash_trading_addresses = set()
        wash_trading = df_forta_alerts[(df_forta_alerts["alertId"] == "NFT-WASH-TRADE")]
        wash_trading["metadata"].apply(lambda x: wash_trading_addresses.update(get_wash_trading_addresses(x)))
        logging.info(f"Got {len(wash_trading_addresses)} wash trading addresses")

        attack_detector_addresses = set()
        attack_detector = df_forta_alerts[(df_forta_alerts["alertId"] == "ATTACK-DETECTOR-1")]
        attack_detector["metadata"].apply(lambda x: attack_detector_addresses.add(get_seaport_order_attacker_address(x)))
        logging.info(f"Got {len(attack_detector_addresses)} attack detector addresses")

        address_poisoning_addresses = set()
        address_poisoning = df_forta_alerts[(df_forta_alerts["alertId"] == "ADDRESS-POISONING") | (df_forta_alerts["alertId"] == "ADDRESS-POISONING-LOW-VALUE") | (df_forta_alerts["alertId"] == "ADDRESS-POISONING-FAKE-TOKEN")]
        address_poisoning["metadata"].apply(lambda x: address_poisoning_addresses.update(get_address_poisoning_addresses(x)))
        logging.info(f"Got {len(address_poisoning_addresses)} address poisoning addresses")

        seaport_order_addresses = set()
        seaport_orders = df_forta_alerts[(df_forta_alerts["alertId"] == "SEAPORT-PHISHING-TRANSFER")]
        seaport_orders["metadata"].apply(lambda x: seaport_order_addresses.add(get_seaport_order_attacker_address(x)))
        logging.info(f"Got {len(seaport_order_addresses)} fraudulent seaport order addresses")

        ice_phishing = df_forta_alerts[(df_forta_alerts["alertId"] == "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS") | (df_forta_alerts["alertId"] == "ICE-PHISHING-PERMITTED-ERC20-TRANSFER")
                                       | (df_forta_alerts["alertId"] == "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS") | (df_forta_alerts["alertId"] == "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS") | (df_forta_alerts["alertId"] == "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL")
                                       | (df_forta_alerts["alertId"] == "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL") | (df_forta_alerts["alertId"] == "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL")]
        ice_phishing_addresses = set()
        ice_phishing["description"].apply(lambda x: ice_phishing_addresses.add(get_ice_phishing_attacker_address(x)))
        logging.info(f"Got {len(ice_phishing_addresses)} ice phishing addresses")

        addresses = set()
        addresses.update(seaport_order_addresses)
        seaport_order_clusters = swap_addresses_with_clusters(list(seaport_order_addresses), df_address_clusters_exploded)
        addresses.update(ice_phishing_addresses)
        ice_phishing_clusters = swap_addresses_with_clusters(list(ice_phishing_addresses), df_address_clusters_exploded)
        addresses.update(attack_detector_addresses)
        attack_detector_clusters = swap_addresses_with_clusters(list(attack_detector_addresses), df_address_clusters_exploded)
        addresses.update(address_poisoning_addresses)
        address_poisoning_clusters = swap_addresses_with_clusters(list(address_poisoning_addresses), df_address_clusters_exploded)
        addresses.update(native_ice_phishing_addresses)
        native_ice_phishing_clusters = swap_addresses_with_clusters(list(native_ice_phishing_addresses), df_address_clusters_exploded)
        addresses.update(wash_trading_addresses)
        wash_trading_clusters = swap_addresses_with_clusters(list(wash_trading_addresses), df_address_clusters_exploded)

        # these are not processed as main attacker address candidates, but need to be combined with other alerts
        sleep_minting_addresses = set()
        sleep_minting = df_forta_alerts[(df_forta_alerts["alertId"] == "SLEEPMINT-3")]
        sleep_minting["description"].apply(lambda x: sleep_minting_addresses.update(get_sleep_minting_addresses(x)))
        logging.info(f"Got {len(sleep_minting_addresses)} sleep minting addresses")
        sleep_minting_clusters = swap_addresses_with_clusters(list(sleep_minting_addresses), df_address_clusters_exploded)


        clusters = swap_addresses_with_clusters(list(addresses), df_address_clusters_exploded)
        logging.info(f"Mapped addresses to {len(clusters)} clusters.")

        for potential_attacker_cluster_lower in clusters:
            try:
                logging.debug(potential_attacker_cluster_lower)
                if "0x000000000000000000000000000" in potential_attacker_cluster_lower:
                    continue
                if len(potential_attacker_cluster_lower.split(",")) > 10:
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


                    # most attacks are straight passthroughs
                    # for most ice phishing, we need more evidence and one of these conditions need to be met
                    if potential_attacker_cluster_lower not in ALERTED_CLUSTERS:
                        if (('SLEEPMINT-3' in alert_ids)
                            or ('MALICIOUS-ACCOUNT-FUNDING' in alert_ids or 'UMBRA-RECEIVE' in alert_ids or 'CEX-FUNDING-1' in alert_ids or 'AK-AZTEC-PROTOCOL-FUNDING' in alert_ids or 'FUNDING-CHANGENOW-NEW-ACCOUNT' in alert_ids or 'FUNDING-TORNADO-CASH' in alert_ids or 'TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION' in alert_ids or 'POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH' in alert_ids or 'MALICIOUS-ACCOUNT-FUNDING' in alert_ids)
                            or ('UNVERIFIED-CODE-CONTRACT-CREATION' in alert_ids or 'FLASHBOT-TRANSACTION' in alert_ids)
                            or ('SUSPICIOUS-TOKEN-CONTRACT-CREATION' in alert_ids)
                            or ('AE-MALICIOUS-ADDR' in alert_ids or 'forta-text-messages-possible-hack' in alert_ids)
                            or ('SCAM' in alert_ids)
                            or ('ATTACK-DETECTOR-1' in alert_ids)
                            or ('SEAPORT-PHISHING-TRANSFER' in alert_ids)
                            or ('ADDRESS-POISONING' in alert_ids or 'ADDRESS-POISONING-LOW-VALUE' in alert_ids or 'ADDRESS-POISONING-FAKE-TOKEN' in alert_ids)
                            or ('NIP-1' in alert_ids)
                            or ('ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS' in alert_ids)
                            or ('NFT-WASH-TRADE' in alert_ids)):
                            tx_count = 0
                            try:
                                tx_count = get_max_transaction_count(w3, potential_attacker_cluster_lower)
                            except Exception as e:
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

                            logging.info(f"Cluster {potential_attacker_cluster_lower} is scammer. Raising alert.")
                            update_alerted_clusters(w3, potential_attacker_cluster_lower)

                            if potential_attacker_cluster_lower in seaport_order_clusters:
                                FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(block_chain_indexer, potential_attacker_cluster_lower, start_date, end_date, involved_clusters, involved_alert_ids, 'SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER', hashes, CHAIN_ID))
                            elif potential_attacker_cluster_lower in native_ice_phishing_clusters:
                                FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(block_chain_indexer, potential_attacker_cluster_lower, start_date, end_date, involved_clusters, involved_alert_ids, 'SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING', hashes, CHAIN_ID))
                            elif potential_attacker_cluster_lower in wash_trading_clusters:
                                FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(block_chain_indexer, potential_attacker_cluster_lower, start_date, end_date, involved_clusters, involved_alert_ids, 'SCAM-DETECTOR-WASH-TRADE', hashes, CHAIN_ID))
                            elif potential_attacker_cluster_lower in attack_detector_clusters:
                                FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(block_chain_indexer, potential_attacker_cluster_lower, start_date, end_date, involved_clusters, involved_alert_ids, 'SCAM-DETECTOR-1', hashes, CHAIN_ID))
                            elif potential_attacker_cluster_lower in address_poisoning_clusters:
                                FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(block_chain_indexer, potential_attacker_cluster_lower, start_date, end_date, involved_clusters, involved_alert_ids, 'SCAM-DETECTOR-ADDRESS-POISONING', hashes, CHAIN_ID))
                            elif potential_attacker_cluster_lower in ice_phishing_clusters:
                                FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(block_chain_indexer, potential_attacker_cluster_lower, start_date, end_date, involved_clusters, involved_alert_ids, 'SCAM-DETECTOR-ICE-PHISHING', hashes, CHAIN_ID))

                            # if we identify a threat and sleep minting is observed as well, we emit an additional sleep minting alert
                            if potential_attacker_cluster_lower in sleep_minting_clusters and 'SLEEPMINT-3' in alert_ids:
                                FINDINGS_CACHE.append(AlertCombinerFinding.alert_combiner(block_chain_indexer, potential_attacker_cluster_lower, start_date, end_date, involved_clusters, involved_alert_ids, 'SCAM-DETECTOR-SLEEP-MINTING', hashes, CHAIN_ID))

                            logging.info(f"Findings count {len(FINDINGS_CACHE)}")
                            persist_state()
                    else:
                        logging.info(f"Cluster {potential_attacker_cluster_lower} already alerted on.")
            except Exception as e:
                logging.warning(f"Error processing address combiner alert 1 {potential_attacker_cluster_lower}: {e} - {traceback.format_exc()}")
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
    if "ICE-PHISHING" in alert["alertId"] or "ADDRESS-POISONING" in alert["alertId"] or "SEAPORT-PHISHING-TRANSFER" in alert["alertId"] or "ATTACK-DETECTOR-1" in alert["alertId"]  or "NIP-1" in alert["alertId"] or "NFT-WASH-TRADE" in alert["alertId"]:
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


def update_alerted_fp_addresses(w3, address: str):
    """
    this function maintains a list clusters; holds up to CLUSTER_QUEUE_SIZE in memory
    :return: None
    """
    global ALERTED_FP_ADDRESSES

    ALERTED_FP_ADDRESSES.append(address.lower())
    logging.info(f"Added {address.lower()} to alerted fp addresses.")
    logging.info(f"ALERTED_FP_ADDRESSES size {len(ALERTED_FP_ADDRESSES)}.")
    if len(ALERTED_FP_ADDRESSES) > ADDRESS_QUEUE_SIZE:
        ALERTED_FP_ADDRESSES.pop(0)


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
            if res.status_code == 200 and len(res.content) > 0:
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

    global ALERTED_FP_ADDRESSES
    logging.info(f"Persisting alerted fp addresses of length {len(ALERTED_FP_ADDRESSES)}.")
    if len(ALERTED_FP_ADDRESSES) < 100:
        logging.info(f"Persist {ALERTED_FP_ADDRESSES} alerted fp addresses from cache")
    persist(ALERTED_FP_ADDRESSES, ALERTED_FP_ADDRESSES_KEY)

    logging.info("Persisted bot state.")


def emit_new_fp_finding(w3):
    global FP_MITIGATION_ADDRESSES
    global CHAIN_ID
    res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/main/scam-detector-py/fp_list.csv')
    content = res.content.decode('utf-8') if res.status_code == 200 else open('fp_list.csv', 'r').read()
    df_fp = pd.read_csv(io.StringIO(content))
    for index, row in df_fp.iterrows():
        chain_id = int(row['chain_id'])
        if chain_id != CHAIN_ID:
            continue
        address = row['address'].lower()
        FP_MITIGATION_ADDRESSES.add(address)
        if address not in ALERTED_FP_ADDRESSES:
            logging.info("Emitting FP mitigation finding")
            update_alerted_fp_addresses(w3, address)
            FINDINGS_CACHE.append(AlertCombinerFinding.alert_FP(address))
            logging.info(f"Findings count {len(FINDINGS_CACHE)}")
            persist_state()


def provide_handle_block(w3, forta_explorer):
    logging.debug("provide_handle_block called")

    def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        logging.debug("handle_block with w3 called")
        global FINDINGS_CACHE
        global MUTEX
        global CHAIN_ID

        if CHAIN_ID == -1:
            logging.error("Chain ID not set")
            return []

        findings = []
        for finding in FINDINGS_CACHE[0:10]:  # 10 findings per block due to size limitation
            findings.append(finding)
        FINDINGS_CACHE = FINDINGS_CACHE[10:]

        if datetime.now().minute == 0:  # every hour
            emit_new_fp_finding(w3)

            logging.info(f"Persisting state at block number {block_event.block_number}.")
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
