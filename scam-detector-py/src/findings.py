from operator import inv
from time import strftime
from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
from datetime import datetime


class AlertCombinerFinding:

    @staticmethod
    def alert_combiner(attacker_address: str, start_date: datetime, end_date: datetime, involved_addresses: set, involved_alerts: set, alert_id: str, hashes: set, chain_id: int) -> Finding:
        involved_addresses = list(involved_addresses)[0:20]
        hashes = list(hashes)[0:10]

        attacker_address_md = {"attacker_address": attacker_address}
        start_date = {"start_date": start_date.strftime("%Y-%m-%d")}
        end_date = {"end_date": end_date.strftime("%Y-%m-%d")}
        involved_addresses = {"involved_addresses_" + str(i): address for i, address in enumerate(involved_addresses, 1)}
        involved_alert_ids = {"involved_alert_id_" + str(i): alert_id for i, alert_id in enumerate(involved_alerts, 1)}
        involved_alert_hashes = {"involved_alert_hashes_" + str(i): alert_id for i, alert_id in enumerate(hashes, 1)}
        meta_data = {**attacker_address_md, **start_date, **end_date, **involved_addresses, **involved_alert_ids, **involved_alert_hashes}

        labels = []
        if alert_id == "SCAM-DETECTOR-ICE-PHISHING" or alert_id == 'SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER' or alert_id == 'SCAM-DETECTOR-1' or alert_id == 'SCAM-DETECTOR-ADDRESS-POISONING' or alert_id == 'SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING' or alert_id == 'SCAM-DETECTOR-WASH-TRADE':
            labels = [Label({
                'entityType': EntityType.Address,
                'label': "scam",
                'entity': attacker_address,
                'confidence': 0.8,
                'remove': "false",
                'metadata': {
                    'alert_id': alert_id,
                    'chain_id': chain_id
                }
    	    })]

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to scam behavior',
            'description': f'{attacker_address} likely involved in an scam ({alert_id})',
            'alert_id': alert_id,
            'type': FindingType.Exploit,
            'severity': FindingSeverity.Critical,
            'metadata': meta_data,
            'labels': labels
        })


    @staticmethod
    def alert_FP(address: str) -> Finding:
        labels = []
        labels = [Label({
                'entityType': EntityType.Address,
                'label': "scam",
                'entity': address,
                'confidence': 0.99,
                'remove': "true"
    	    })]

        return Finding({
            'name': 'Scam detector identified an EOA that was incorrectly alerted on. Emitting false positive alert.',
            'description': f'{address} likely not involved in scam (SCAM-DETECTOR-ICE-PHISHING-FALSE-POSITIVE)',
            'alert_id': 'SCAM-DETECTOR-ICE-PHISHING-FALSE-POSITIVE',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': labels
        })

