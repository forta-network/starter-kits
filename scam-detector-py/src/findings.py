from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
from datetime import datetime
import pandas as pd
import logging

class ScamDetectorFinding:
    @staticmethod
    def get_threat_description_url(alert_ids: set) -> list:
        threat_detection_urls = []
        url = "https://forta.org/attacks"
        for alert_id in alert_ids:
            if 'ICE-PHISHING' in alert_id:
                threat_detection_urls.append(url + "#ice-phishing")
            elif "SLEEPMINT" in alert_id:
                threat_detection_urls.append("#sleep-minting")
            else:
                threat_detection_urls.append(url)
        return threat_detection_urls
        
    @staticmethod
    def scam_finding_model(block_chain_indexer, scammer_cluster: str, score: float, alert_id: str, feature_vector: pd.DataFrame, alerts: list, chain_id: int) -> Finding:  # alerts are list of tuples (bot_id, alert_id, alert_hash)
        feature_vector_str = ""
        for i, row in feature_vector.iterrows():
            for col in feature_vector.columns:
                feature_vector_str += f"{row[col]},"
        
        logging.info(f"Feature vector: {feature_vector_str}")
        
        score_dict = {"score": str(score)}

        bot_id_alert_id = set()
        alert_ids = set()
        for bot_id_1, alert_id_1, alert_hash in alerts:
            bot_id_alert_id.add((bot_id_1, alert_id_1))
            alert_ids.add(alert_id_1)
        
        threat_detection_urls = ScamDetectorFinding.get_threat_description_url(alert_ids)

        example_alerts = dict()
        for (bot_id_1, alert_id_1) in bot_id_alert_id:
            for bot_id_2, alert_id_2, alert_hash in alerts:
                if bot_id_1 == bot_id_2 and alert_id_1 == alert_id_2:
                    example_alerts[(bot_id_1, alert_id_1)] = (bot_id_1, alert_id_1, alert_hash)
                    break

        example_base_alerts = {"base_alert_" + str(i): f"{bot_id_1},{alert_id_1},{alert_hash}" for i, (bot_id_1, alert_id_1, alert_hash) in enumerate(example_alerts.values(), 1)}
        meta_data = {**example_base_alerts, **score_dict}
        meta_data["feature_vector"] = feature_vector_str

        labels = []
        for scammer_address in scammer_cluster.split(","):
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer-eoa",
                'entity': scammer_address,
                'confidence': str(score),
                'metadata': {
                    'alert_ids': ','.join(str(x) for x in alert_ids),
                    'chain_id': chain_id,
                    'threat_detection_urls': ','.join(str(x) for x in threat_detection_urls),
                }
    	    }))

            # get all deployed contracts by EOA and add label for those using etherscan or allium
            contracts = block_chain_indexer.get_contracts(scammer_address, chain_id)
            for contract in contracts:
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': "scammer-contract",
                    'entity': contract,
                    'confidence': str(score),
                    'metadata': {
                        'alert_ids': ','.join(str(x) for x in alert_ids),
                        'chain_id': chain_id,
                        'threat_detection_urls': ','.join(str(x) for x in threat_detection_urls),
                    }
    	        }))

        if "SCAM-DETECTOR-MODEL-1" in alert_id:
            return Finding({
                'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
                'description': f'{scammer_cluster} likely involved in an attack ({alert_id})',
                'alert_id': alert_id,
                'type': FindingType.Exploit,
                'severity': FindingSeverity.Critical,
                'metadata': meta_data,
                'labels': labels
            })
        else: 
            return Finding({
                'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
                'description': f'{scammer_cluster} likely involved in an attack ({alert_id})',
                'alert_id': alert_id,
                'type': FindingType.Exploit,
                'severity': FindingSeverity.Low,
                'metadata': meta_data,
                'labels': labels
            })
        

    @staticmethod
    def scam_finding_similar(block_chain_indexer, new_scammer_address_lower:str, new_scammer_contract_address:str, scammer_address:str, scammer_contract_address:str, similarity_score: float, alert_id: str, chain_id: int) -> Finding:
        metadata = {"similarity_score": str(similarity_score),
                    "new_scammer_contract_address": new_scammer_contract_address,
                    "scammer_contract_address": scammer_contract_address
                    }
        
        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "scammer-eoa",
            'entity': new_scammer_address_lower,
            'confidence': str(similarity_score),
            'metadata': {
                'alert_id': alert_id,
                'threat_detection_url': "https://forta.org/attacks",
                'chain_id': chain_id
            }
        }))
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "scammer-contract",
            'entity': new_scammer_contract_address,
            'confidence': str(similarity_score),
            'metadata': {
                'alert_id': alert_id,
                'threat_detection_url': "https://forta.org/attacks",
                'chain_id': chain_id
            }
        }))

           

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
            'description': f"{new_scammer_address_lower} deployed a new contract with similar code to previously identified scammer {scammer_address}",
            'alert_id': alert_id,
            'type': FindingType.Exploit,
            'severity': FindingSeverity.Critical,
            'metadata': metadata,
            'labels': labels
        })


    @staticmethod
    def scam_finding_manual(block_chain_indexer, scammer_cluster: str, threat_category: str, reported_by: str, chain_id: int) -> Finding:
        labels = []

        alert_id_threat_category = threat_category.upper().replace(" ", "-")

        for scammer_address in scammer_cluster.split(","):
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer-eoa",
                'entity': scammer_address,
                'confidence': 1,
                'metadata': {
                    'alert_ids': "SCAM-DETECTOR-MANUAL-"+alert_id_threat_category,
                    'reported_by': reported_by,
                    'chain_id': chain_id
                }
            }))

            # get all deployed contracts by EOA and add label for those using etherscan or allium
            contracts = block_chain_indexer.get_contracts(scammer_cluster, chain_id)
            for contract in contracts:
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': "scammer-contract",
                    'entity': contract,
                    'confidence': 1,
                    'metadata': {
                        'alert_ids': "SCAM-DETECTOR-MANUAL-" + alert_id_threat_category,
                        'reported_by': reported_by,
                        'chain_id': chain_id
                    }
                }))

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
            'description': f'{scammer_cluster} likely involved in an attack (SCAM-DETECTOR-MANUAL-{alert_id_threat_category})',
            'alert_id': "SCAM-DETECTOR-MANUAL-" + alert_id_threat_category,
            'type': FindingType.Exploit,
            'severity': FindingSeverity.Critical,
            'metadata': {"reported_by": reported_by},
            'labels': labels
        })

    @staticmethod
    def alert_FP(cluster: str) -> Finding:
        labels = []
        for benign_address in cluster.split(","):
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer",
                'entity': benign_address,
                'confidence': 0.99,
                'remove': "true"
            }))

        return Finding({
            'name': 'Scam detector identified an EOA that was incorrectly alerted on. Emitting false positive alert.',
            'description': f'{cluster} likely not involved in scam (SCAM-DETECTOR-FALSE-POSITIVE)',
            'alert_id': 'SCAM-DETECTOR-FALSE-POSITIVE',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': labels
        })

