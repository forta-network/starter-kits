from operator import inv
from time import strftime
from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
from datetime import datetime


class AlertCombinerFinding:

    @staticmethod
    def alert_combiner(block_chain_indexer, scammer_addresses: str, start_date: datetime, end_date: datetime, involved_addresses: set, involved_alerts: set, alert_id: str, hashes: set, chain_id: int) -> Finding:
        involved_addresses = list(involved_addresses)[0:20]
        hashes = list(hashes)[0:10]

        attacker_address_md = {"attacker_address": scammer_addresses}
        attacker_address_md = {"scammer_addresses": scammer_addresses}
        start_date = {"start_date": start_date.strftime("%Y-%m-%d")}
        end_date = {"end_date": end_date.strftime("%Y-%m-%d")}
        involved_addresses = {"involved_addresses_" + str(i): address for i, address in enumerate(involved_addresses, 1)}
        involved_alert_ids = {"involved_alert_id_" + str(i): alert_id for i, alert_id in enumerate(involved_alerts, 1)}
        involved_alert_hashes = {"involved_alert_hashes_" + str(i): alert_id for i, alert_id in enumerate(hashes, 1)}
        meta_data = {**attacker_address_md, **start_date, **end_date, **involved_addresses, **involved_alert_ids, **involved_alert_hashes}

        labels = []
        if alert_id in ["SCAM-DETECTOR-ICE-PHISHING", 'SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER',' SCAM-DETECTOR-1', 'SCAM-DETECTOR-ADDRESS-POISONING', 'SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-WASH-TRADE', 'SCAM-DETECTOR-SLEEP-MINTING']:
            labels = []
            for scammer_address in scammer_addresses.split(","):
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': "scammer-eoa",
                    'entity': scammer_address,
                    'confidence': 0.8,
                    'metadata': {
                        'alert_id': alert_id,
                        'chain_id': chain_id
                    }
                }))

                # get all deployed contracts by EOA and add label for those using etherscan or allium
                contracts = block_chain_indexer.get_contracts(scammer_address, chain_id)
                for contract in contracts:
                    labels.append(Label({
                        'entityType': EntityType.Address,
                        'label': "scammer-contract",
                        'entity': contract,
                        'confidence': 0.8,
                        'metadata': {
                            'alert_ids': alert_id,
                            'chain_id': chain_id
                        }
                    }))

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to scam behavior',
            'description': f'{scammer_addresses} likely involved in an scam ({alert_id})',
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
                'label': "scammer-eoa",
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

