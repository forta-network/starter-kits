from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
from datetime import datetime
import pandas as pd


class ScamDetectorFinding:

    @staticmethod
    def scam_finding(scammer_cluster: str, score: set, feature_vector: pd.DataFrame, alert_hash_sample: list, chain_id: int) -> Finding:
        
        attacker_address_md = {"attacker_addresses": scammer_cluster}
        involved_alert_ids = {"involved_alert_id_" + str(i): alert_id for i, alert_id in enumerate(involved_alerts, 1)}
        meta_data = {**attacker_address_md, **involved_alert_ids}

        #TODO - get all deployed contracts by EOA and add label for those using etherscan or allium

        labels = []
        for scammer_address in scammer_cluster.split(","):
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer",
                'entity': scammer_address,
                'confidence': score,
                'remove': "false",
                'metadata': {
                    'alert_id': alert_id, #TODO - create explanation from model
                    'chain_id': chain_id
                }
    	    }))

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
            'description': f'{scammer_address} likely involved in an attack (SCAM-DETECTOR-1)',
            'alert_id': "SCAM-DETECTOR-1",
            'type': FindingType.Exploit,
            'severity': FindingSeverity.Critical,
            'metadata': meta_data,
            'labels': labels
        })


    @staticmethod
    def alert_FP(benign_address: str) -> Finding:
        labels = []
        labels = [Label({
            'entityType': EntityType.Address,
            'label': "scammer",
            'entity': benign_address,
            'confidence': 0.99,
            'remove': "true"
        })]

        return Finding({
            'name': 'Scam detector identified an EOA that was incorrectly alerted on. Emitting false positive alert.',
            'description': f'{benign_address} likely not involved in scam (SCAM-DETECTOR-1-FALSE-POSITIVE)',
            'alert_id': 'SCAM-DETECTOR-1-FALSE-POSITIVE',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': labels
        })

