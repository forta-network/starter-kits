from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType, get_labels
import pandas as pd
import json
import os
import logging
import traceback
import forta_agent
import hashlib

from src.constants import ATTACK_DETECTOR_BOT_ID, ATTACK_DETECTOR_BETA_BOT_ID, NUMBER_BOT_SOURCE
from src.utils import Utils


class AlertCombinerFinding:

    @staticmethod
    def get_bot_name() -> str:
        package = json.load(open("package.json"))
        return package["name"]

    @staticmethod
    def create_finding(block_chain_indexer, addresses: str, victim_address: str, victim_name, anomaly_score: float, severity: FindingSeverity, alert_id: str, 
        alert_event: forta_agent.alert_event.AlertEvent, alert_data: pd.DataFrame, victim_metadata: dict, anomaly_scores_by_stage: pd.DataFrame, chain_id: int, bot_sources: set) -> Finding:
        # alert_data -> 'stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'addresses', 'transaction_hash', 'address_filter' (+ 'chain_id' for L2s)

        #only emit ATTACK-DETECTOR-4 and ATTACK-DETECTOR-5 alerts in test local or beta environments, but not production
        if ((alert_id == "ATTACK-DETECTOR-4" or alert_id == "ATTACK-DETECTOR-5" or alert_id == "ATTACK-DETECTOR-6" or alert_id == "ATTACK-DETECTOR-7") and "beta" not in AlertCombinerFinding.get_bot_name() and ('NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'))):
            return None

        bot_sources_sorted = list(bot_sources)
        bot_sources_sorted.sort()

        anomaly_scores = {}
        for index, row in anomaly_scores_by_stage.iterrows():
            anomaly_scores[f'anomaly_score_stage_{row["stage"]}'] = row["anomaly_score"]
        attacker_address = {"attacker_address": addresses}
        anomaly_score_dict = {"anomaly_score": anomaly_score}
        bot_source_dict = {"bot_source": "/".join(bot_sources_sorted)}
        consensus_dict = {"consensus": len(bot_sources) * 1.0 / NUMBER_BOT_SOURCE}
        involved_addresses = set()
        alert_data[alert_data["addresses"].notnull()]["addresses"].apply(lambda x: [involved_addresses.add(item) for item in x])
        involved_addresses = list(involved_addresses)[0:500]
        involved_addresses = {"involved_addresses_" + str(i): address for i, address in enumerate(involved_addresses, 1)}

        alerts = alert_data[['bot_id', 'alert_id', 'alert_hash']].drop_duplicates(inplace=False)
        alerts = alerts.head(100)
        involved_alerts = {"involved_alerts_" + str(index): ','.join([row['bot_id'], row['alert_id'], row['alert_hash']]) for index, row in alerts.iterrows()}

        # Extract Bloom filters per involved alert
        involved_address_bloom_filters = {}
        for index, row in alerts.iterrows():
            filter_data = alert_data.loc[alert_data['alert_hash'] == row['alert_hash'], 'address_filter'].values
            if filter_data[0] is not None:
                involved_address_bloom_filters[f'involved_address_bloom_filter_{index}'] = ','.join(str(item) for item in filter_data[0])
            else:
                involved_address_bloom_filters[f'involved_address_bloom_filter_{index}'] = '' 

        meta_data = {**attacker_address, **victim_metadata, **anomaly_scores, **anomaly_score_dict, **involved_addresses, **involved_alerts, **involved_address_bloom_filters, **bot_source_dict, **consensus_dict}

        involved_addresses_list = [address for key, address in meta_data.items() if key.startswith('involved_addresses_')]
        victim_clause = f" on {victim_name} ({victim_address.lower()})" if victim_address else ""
        anomaly_clause = f" Anomaly score: {anomaly_score}" if anomaly_score > 0 else ""

        confidence = 0.2
        if "BlockSec" in bot_sources_sorted:
            confidence = 0.8

        labels = []
        for address in addresses.split(','):
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "attacker-eoa",
                'entity': address,
                'confidence': confidence,
                'metadata': {
                    'alert_id': alert_id,
                    'chain_id': chain_id,
                    'threat_description_url': 'https://forta.org/attacks/'
                }
            }))

            try:
                if len(addresses.split(",")) > 30:
                    logging.info(f"Too many addresses in cluster, skipping contract lookup")
                    continue
                contracts = block_chain_indexer.get_contracts(address, chain_id)
                for contract in contracts:
                    labels.append(Label({
                        'entityType': EntityType.Address,
                        'label': "attacker-contract",
                        'entity': contract,
                        'confidence': confidence,
                        'metadata': {
                            'alert_ids': alert_id,
                            'chain_id': chain_id,
                            'threat_description_url': 'https://forta.org/attacks/'
                        }
                    }))
            except Exception as e:
                logging.warning(f"Error getting contracts for {address} {e}")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "findings.create_finding", traceback.format_exc()))

        unique_key = hashlib.sha256(f'{addresses},{victim_clause},{alert_id},{"/".join(bot_sources_sorted)}'.encode()).hexdigest()
        logging.info(f"Unique key of {addresses},{victim_clause},{alert_id},{'/'.join(bot_sources_sorted)}: {unique_key}")

        if alert_id == "ATTACK-DETECTOR-PREPARATION":
            description = f'{addresses} likely involved in an attack preparation ({alert_event.alert_hash}){victim_clause}. {anomaly_clause}'
        else:
            description = f'{addresses} likely involved in an attack ({alert_event.alert_hash}){victim_clause}. {anomaly_clause}'

        return Finding({
                       'name': 'Attack detector identified an EOA with behavior consistent with an attack',
                       'description': description,
                       'alert_id': alert_id,
                       'type': FindingType.Exploit,
                       'severity': severity,
                       'metadata': meta_data,
                       'unique_key': unique_key,
                       'labels': labels,
                       'addresses': involved_addresses_list
                       })

    @staticmethod
    def alert_FP(address: str, label: str, metadata_list: list) -> Finding:

        labels = []
        for metadata in metadata_list:
            labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': label,
                    'entity': address,
                    'confidence': 0.99,
                    'remove': "true",
                    'metadata': metadata

                }))
            
        unique_key = hashlib.sha256(f'{address},{label},{metadata_list},ATTACK-DETECTOR-FALSE-POSITIVE'.encode()).hexdigest()
        logging.info(f"Unique key of {address},{label},{metadata_list},ATTACK-DETECTOR-FALSE-POSITIVE: {unique_key}")

        return Finding({
            'name': 'Attack detector identified an address that was incorrectly alerted on. Emitting false positive alert.',
            'description': f'{address} likely not involved in an attack (ATTACK-DETECTOR-FALSE-POSITIVE)',
            'alert_id': 'ATTACK-DETECTOR-FALSE-POSITIVE',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': labels,
            'unique_key': unique_key
        })
    
    @staticmethod
    def attack_finding_manual(block_chain_indexer, attacker_cluster: str, reported_by: str, chain_id: int, test_flag = False) -> Finding:
        label_doesnt_exist = False
        labels = []

        for attacker_address in attacker_cluster.split(","):
            source_id = ATTACK_DETECTOR_BETA_BOT_ID if Utils.is_beta() else ATTACK_DETECTOR_BOT_ID
            label_query_options_dict = {    
                "entities": [attacker_address],  
                "source_ids": [source_id], 
                "state": True,                   
                "first": 10,                      
            }
            
            logging.info(f"Querying for existing label: {label_query_options_dict}")
            labels_response = get_labels(label_query_options_dict)
            if test_flag or not labels_response.labels:
                logging.info(f"Label doesn't exist for {attacker_address}")
                label_doesnt_exist = True
            else:
                logging.info(f"Label exists for {attacker_address}")

            labels.append(Label({
                'entityType': EntityType.Address,
                'label': 'attacker-eoa',
                'entity': attacker_address,
                'confidence': 1,
                'metadata': {
                    'address_type': 'EOA',
                    'chain_id': chain_id,
                    'reported_by': reported_by,
                }
            }))
            if len(attacker_cluster.split(",")) > 30:
                logging.info(f"Too many addresses in cluster, skipping contract lookup")
                continue
            contracts = block_chain_indexer.get_contracts(attacker_cluster, chain_id)
            for contract in contracts:
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': 'attacker-contract',
                    'entity': contract,
                    'confidence': 1,
                    'metadata': {
                        'address_type': 'contract',
                        'chain_id': chain_id,
                        'reported_by': reported_by,
                        'deployer_info': f"Deployer {attacker_address} involved in attack; this contract may or may not be related to this particular attack, but was created by the attacker.",                       
                    }
                }))

        if label_doesnt_exist:
            return Finding({
                'name': 'Attack detector identified an EOA with past alerts mapping to attack behavior',
                'description': f'{attacker_cluster} likely involved in an attack (ATTACK-DETECTOR-MANUAL)',
                'alert_id': "ATTACK-DETECTOR-MANUAL",
                'type': FindingType.Exploit,
                'severity': FindingSeverity.Critical,
                'metadata': {"reported_by": reported_by},
                'labels': labels
            })