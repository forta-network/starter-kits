from operator import inv
from time import strftime
from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
from datetime import datetime
import requests


class AlertCombinerFinding:

    @staticmethod
    def get_threat_description_url(alert_id: str) -> str:
        url = "https://forta.org/attacks"
        if alert_id == "SCAM-DETECTOR-ICE-PHISHING":
            return url + "#ice-phishing"
        elif alert_id == "SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER":
            return url + "#fraudulent-seaport-order"
        elif alert_id == "SCAM-DETECTOR-ADDRESS-POISONING" or alert_id == "SCAM-DETECTOR-ADDRESS-POISONER":
            return url + "#address-poisoning"
        elif alert_id == "SCAM-DETECTOR-NATIVE-ICE-PHISHING":
            return url + "#native-ice-phishing"
        elif alert_id == "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING":
            return url + "#native-ice-phishing"
        elif alert_id == "SCAM-DETECTOR-WASH-TRADE":
            return url + "#wash-trading"
        elif alert_id == "SCAM-DETECTOR-SLEEP-MINTING":
            return url + "#sleep-minting"
        else:
            return url

    @staticmethod
    def alert_similar_contract(block_chain_indexer, row, chain_id:int) -> Finding:

        # {"alert_hash":"0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016",
        #  "new_scammer_contract_address":"0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2",
        #  "new_scammer_eoa":"0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0",
        #  "scammer_contract_address":"0xe22536ac6f6a20dbb283e7f61a880993eab63313",
        #  "scammer_eoa":"0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e",
        #  "similarity_hash":"68e6432db785f93986a9d49b19077067f8b694612f2bc1e8ef5cd38af2c8727e",
        #  "similarity_score":"0.9347575306892395"}

        alert_hash = row["metadata"]["alertHash"]
        existing_scammer_contract_address = row["metadata"]["scammerContractAddress"]
        existing_scammer_address = row["metadata"]["scammerEoa"]
        scammer_contract_address = row["metadata"]["newScammerContractAddress"]
        scammer_address = row["metadata"]["newScammerEoa"]
        similarity_score = row["metadata"]["similarityScore"]

        alert_id = "SCAM-DETECTOR-SIMILAR-CONTRACT"

        label_api = "https://api.forta.network/labels/state?sourceIds=0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23&entities="
        res = requests.get(label_api + existing_scammer_contract_address.lower())
        original_alert_id = ""
        if res.status_code == 200:
            labels = res.json()
            if 'events' in labels.keys() and len(labels['events']) > 0:
                label_metadata = labels['events'][0]['label']['metadata']
                original_alert_id = label_metadata[0][len("alert_ids="):]
        
        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "scammer-eoa",
            'entity': scammer_address,
            'confidence': 0.7,
            'metadata': {
                'alert_id': alert_id,
                'chain_id': chain_id,
                'similar_contract_alert_ids': original_alert_id,
                'threat_description_url': AlertCombinerFinding.get_threat_description_url(alert_id)
            }
        }))

        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "scammer-contract",
            'entity': scammer_contract_address,
            'confidence': 0.7,
            'metadata': {
                'alert_id': alert_id,
                'chain_id': chain_id,
                'similar_contract_alert_ids': original_alert_id,
                'threat_description_url': AlertCombinerFinding.get_threat_description_url(alert_id)
            }
        }))

        # get all deployed contracts by EOA and add label for those using etherscan or allium
        contracts = block_chain_indexer.get_contracts(scammer_address, chain_id)
        for contract in contracts:
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer-contract",
                'entity': contract,
                'confidence': 0.6,
                'metadata': {
                    'alert_ids': alert_id,
                    'chain_id': chain_id,
                    'similar_contract_alert_ids': original_alert_id,
                    'deployer': scammer_address,
                    'deployer_info': f"Deployer involved in {alert_id} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                    'threat_description_url': AlertCombinerFinding.get_threat_description_url(alert_id)
                }
            }))

        metadata = {}
        metadata['attacker_address'] = scammer_address
        metadata['attacker_contract_address'] = scammer_contract_address
        metadata['existing_attacker_address'] = existing_scammer_address
        metadata['existing_attacker_contract_address'] = existing_scammer_contract_address
        metadata['similarity_score'] = similarity_score
        metadata['involved_alert_id_0'] = original_alert_id
        metadata['involved_alert_hashes_0'] = alert_hash

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to scam behavior',
            'description': f'{scammer_address} likely involved in a scam ({alert_id})',
            'alert_id': alert_id,
            'type': FindingType.Scam,
            'severity': FindingSeverity.Critical,
            'metadata': metadata,
            'labels': labels
        })

    @staticmethod
    def alert_combiner(block_chain_indexer, scammer_addresses: str, start_date: datetime, end_date: datetime, involved_addresses: set, involved_alerts: set, alert_id: str, hashes: set, chain_id: int) -> Finding:
        involved_addresses = list(involved_addresses)[0:10]
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
        if alert_id in ["SCAM-DETECTOR-ICE-PHISHING", 'SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER',' SCAM-DETECTOR-1', 'SCAM-DETECTOR-ADDRESS-POISONER', 'SCAM-DETECTOR-ADDRESS-POISONING', 'SCAM-DETECTOR-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-WASH-TRADE', 'SCAM-DETECTOR-SLEEP-MINTING']:
            labels = []
            for scammer_address in scammer_addresses.split(","):
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': "scammer-eoa",
                    'entity': scammer_address,
                    'confidence': 0.8,
                    'metadata': {
                        'alert_id': alert_id,
                        'chain_id': chain_id,
                        'threat_description_url': AlertCombinerFinding.get_threat_description_url(alert_id)
                    }
                }))

                # get all deployed contracts by EOA and add label for those using etherscan or allium
                contracts = block_chain_indexer.get_contracts(scammer_address, chain_id)
                for contract in contracts:
                    labels.append(Label({
                        'entityType': EntityType.Address,
                        'label': "scammer-contract",
                        'entity': contract,
                        'confidence': 0.7,
                        'metadata': {
                            'alert_ids': alert_id,
                            'chain_id': chain_id,
                            'deployer': scammer_address,
                            'deployer_info': f"Deployer involved in {alert_id} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                            'threat_description_url': AlertCombinerFinding.get_threat_description_url(alert_id)
                        }
                    }))

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to scam behavior',
            'description': f'{scammer_addresses} likely involved in a scam ({alert_id})',
            'alert_id': alert_id,
            'type': FindingType.Scam,
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
            'description': f'{address} likely not involved in a scam (SCAM-DETECTOR-ICE-PHISHING-FALSE-POSITIVE)',
            'alert_id': 'SCAM-DETECTOR-ICE-PHISHING-FALSE-POSITIVE',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': labels
        })

