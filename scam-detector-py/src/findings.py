from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
from datetime import datetime
import pandas as pd
from blockchain_indexer_service import BlockChainIndexer


class ScamDetectorFinding:

    @staticmethod
    def scam_finding_model(block_chain_indexer, scammer_cluster: str, score: float, feature_vector: pd.DataFrame, alerts: list, chain_id: int) -> Finding:  # alerts are list of tuples (bot_id, alert_id, alert_hash)

        feature_vector = {"feature_vector": feature_vector.to_json()}

        bot_id_alert_id = set()
        for bot_id, alert_id, alert_hash in alerts:
            bot_id_alert_id.add((bot_id, alert_id))
        
        example_alerts = dict()
        for (bot_id, alert_id) in bot_id_alert_id:
            for bot_id_1, alert_id_1, alert_hash in alerts:
                if bot_id == bot_id_1 and alert_id == alert_id_1:
                    example_alerts[(bot_id, alert_id)] = (bot_id, alert_id, alert_hash)
                    break

        example_base_alerts = {"base_alert_" + str(i): f"{bot_id},{alert_id},{alert_hash}" for i, (bot_id, alert_id, alert_hash) in enumerate(example_alerts.values(), 1)}
        meta_data = {**feature_vector, **example_base_alerts}

        labels = []
        for scammer_address in scammer_cluster.split(","):
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer",
                'entity': scammer_address,
                'confidence': score,
                'remove': "false",
                'metadata': {
                    'alert_ids': "SCAM-DETECTOR-MODEL-1",
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
                    'confidence': score,
                    'remove': "false",
                    'metadata': {
                        'alert_ids': "SCAM-DETECTOR-MODEL-1",
                        'chain_id': chain_id
                    }
    	        }))

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
            'description': f'{scammer_address} likely involved in an attack (SCAM-DETECTOR-MODEL-1)',
            'alert_id': "SCAM-DETECTOR-MODEL-1",
            'type': FindingType.Exploit,
            'severity': FindingSeverity.Critical,
            'metadata': meta_data,
            'labels': labels
        })
    
    @staticmethod
    def scam_finding_manual(block_chain_indexer, scammer_cluster: str, comment: str, chain_id: int) -> Finding:
        labels = []
        for scammer_address in scammer_cluster.split(","):
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer",
                'entity': scammer_address,
                'confidence': 1,
                'remove': "false",
                'metadata': {
                    'alert_ids': "SCAM-DETECTOR-MANUAL",
                    'comment': comment,
                    'chain_id': chain_id
                }
            }))

            # get all deployed contracts by EOA and add label for those using etherscan or allium
            contracts = block_chain_indexer.get_contracts(scammer_cluster, chain_id)
            for contract in contracts:
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': "scammer",
                    'entity': contract,
                    'confidence': 1,
                    'remove': "false",
                    'metadata': {
                        'alert_ids': "SCAM-DETECTOR-MANUAL",
                        'comment': comment,
                        'chain_id': chain_id
                    }
                }))

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
            'description': f'{scammer_address} likely involved in an attack (SCAM-DETECTOR-MANUAL)',
            'alert_id': "SCAM-DETECTOR-MANUAL",
            'type': FindingType.Exploit,
            'severity': FindingSeverity.Critical,
            'metadata': {"comment": comment},
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
            'description': f'{benign_address} likely not involved in scam (SCAM-DETECTOR-1-FALSE-POSITIVE)',
            'alert_id': 'SCAM-DETECTOR-1-FALSE-POSITIVE',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': labels
        })

