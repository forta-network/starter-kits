from operator import inv
from time import strftime
from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType, get_labels
from datetime import datetime
import requests
import logging

from utils import Utils
from constants import CONFIDENCE_MAPPINGS

class ScamDetectorFinding:

    @staticmethod
    def get_threat_description_url(alert_id: str) -> str:
        url = "https://forta.org/attacks"
        if alert_id == "SCAM-DETECTOR-ICE-PHISHING":
            return url + "#ice-phishing"
        elif alert_id == "SCAM-DETECTOR-FRAUDULENT-NFT-ORDER":
            return url + "#fraudulent-nft-order"
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
        elif alert_id == "SCAM-DETECTOR-HARD-RUG-PULL":
            return url + "#rug-pull"
        elif alert_id == "SCAM-DETECTOR-SOFT-RUG-PULL":
            return url + "#rug-pull"
        elif alert_id == "SCAM-DETECTOR-RAKE-TOKEN":
            return url + "#rake-token"
        else:
            return url

    @staticmethod
    def alert_similar_contract(block_chain_indexer, base_bot_alert_id: str, base_bot_alert_hash: str, metadata: dict, chain_id:int) -> Finding:

        # {"alert_hash":"0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016",
        #  "new_scammer_contract_address":"0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2",
        #  "new_scammer_eoa":"0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0",
        #  "scammer_contract_address":"0xe22536ac6f6a20dbb283e7f61a880993eab63313",
        #  "scammer_eoa":"0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e",
        #  "similarity_hash":"68e6432db785f93986a9d49b19077067f8b694612f2bc1e8ef5cd38af2c8727e",
        #  "similarity_score":"0.9347575306892395"}

        alert_hash = metadata["alertHash"] if "alertHash" in metadata else metadata["alert_hash"]
        existing_scammer_contract_address = metadata["scammerContractAddress"] if "scammerContractAddress" in metadata else metadata["scammer_contract_address"]
        existing_scammer_address = metadata["scammerEoa"] if "scammerEoa" in metadata else metadata["scammer_eoa"]
        scammer_contract_address = metadata["newScammerContractAddress"] if "newScammerContractAddress" in metadata else metadata["new_scammer_contract_address"]
        scammer_address = metadata["newScammerEoa"] if "newScammerEoa" in metadata else metadata["new_scammer_eoa"]
        similarity_score = metadata["similarityScore"] if "similarityScore" in metadata else metadata["similarity_score"]

        alert_id = "SCAM-DETECTOR-SIMILAR-CONTRACT"

        original_alert_ids = set()  # SCAM-DETECTOR-* alert_ids of the original scammer
        response = get_labels({'entities': [existing_scammer_contract_address.lower()],
                    'sourceIds': ['0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23'],
                    'state': True})
        labels = response.labels
        for label in labels:
            for metadata_keys in label.metadata.keys():
                if 'alert_ids' in metadata_keys:
                    original_alert_id = label.metadata["alert_ids"]
                    original_alert_ids.add(original_alert_id)
                    logging.info(f"retrieved original alert id for label {existing_scammer_contract_address.lower()}: {original_alert_id}")
        

        if len(original_alert_ids.intersection(set(['SCAM-DETECTOR-ADDRESS-POISONER', 'SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-HARD-RUG-PULL', 'SCAM-DETECTOR-SOFT-RUG-PULL', 'SCAM-DETECTOR-RAKE-TOKEN'])))>0:
            labels = []
            confidence = CONFIDENCE_MAPPINGS[alert_id]
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer-eoa",
                'entity': scammer_address,
                'confidence': confidence,
                'metadata': {
                    'alert_ids': alert_id,  # SCAM-DETECTOR-SIMILAR-CONTRACT alert id; alert hash is unknown (or rather in source info this label is being decorated with)
                    'chain_id': chain_id,
                    'base_bot_alert_ids': base_bot_alert_id,  # base bot alert id: contract similarity alert id
                    'base_bot_alert_hashes': base_bot_alert_hash,
                    'info': f"This scammer {scammer_address} deployed a contract {scammer_contract_address} that is similar to a contract {existing_scammer_contract_address} deployed by a known scammer {existing_scammer_address} involved in {original_alert_ids} scam (alert hash: {alert_hash}).",
                    'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                    'bot_version': Utils.get_bot_version()
                }
            }))

            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer-contract",
                'entity': scammer_contract_address,
                'confidence': confidence,
                'metadata': {
                    'alert_ids': "SCAM-DETECTOR-SIMILAR-CONTRACT",
                    'chain_id': chain_id,
                    'base_bot_alert_ids': base_bot_alert_id,  # base bot alert id: contract similarity alert id
                    'base_bot_alert_hashes': base_bot_alert_hash,
                    'deployer_info': f"Deployer {scammer_address} deployed a contract {scammer_contract_address} that is similar to a contract {existing_scammer_contract_address} deployed by a known scammer {existing_scammer_address} involved in {original_alert_ids} scam (alert hash: {alert_hash}); this contract may or may not be related to this particular scam, but was created by the scammer.",
                    'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                    'bot_version': Utils.get_bot_version()
                }
            }))

            # get all deployed contracts by EOA and add label for those using etherscan or allium
            try:
                contracts = block_chain_indexer.get_contracts(scammer_address, chain_id)
                for contract in contracts:
                    labels.append(Label({
                        'entityType': EntityType.Address,
                        'label': "scammer-contract",
                        'entity': contract,
                        'confidence': confidence * 0.8,
                        'metadata': {
                            'alert_ids': "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT",
                            'chain_id': chain_id,
                            'base_bot_alert_ids': base_bot_alert_id,  # base bot alert id: contract similarity alert id
                            'base_bot_alert_hashes': base_bot_alert_hash,
                            'deployer_info': f"Deployer {scammer_address} involved in {original_alert_ids} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                            'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                            'bot_version': Utils.get_bot_version()
                        }
                    }))
            except Exception as e:
                logging.warning(f"Error getting contracts for scammer address {scammer_address}: {e}")

            metadata = {}
            metadata['scammer_address'] = scammer_address
            metadata['scammer_contract_address'] = scammer_contract_address
            metadata['existing_scammer_address'] = existing_scammer_address
            metadata['existing_scammer_contract_address'] = existing_scammer_contract_address
            metadata['similarity_score'] = similarity_score
            metadata['involved_alert_id_1'] = original_alert_id
            metadata['involved_alert_hash_1'] = alert_hash

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
    def scam_finding(block_chain_indexer, scammer_addresses: str, start_date: datetime, end_date: datetime, scammer_contract_addresses: set, involved_addresses: set, involved_alert_ids: set, alert_id: str, involved_alert_hashes: set, chain_id: int) -> Finding:
        involved_addresses = list(involved_addresses)[0:10]
        involved_alert_hashes = list(involved_alert_hashes)[0:10]

        attacker_address_md_dict = {"scammer_addresses": scammer_addresses}
        start_date_dict = {"start_date": start_date.strftime("%Y-%m-%d")}
        end_date_dict = {"end_date": end_date.strftime("%Y-%m-%d")}
        involved_addresses_dict = {"involved_addresses_" + str(i): address for i, address in enumerate(involved_addresses, 1)}
        involved_alert_ids_dict = {"involved_alert_id_" + str(i): alert_id for i, alert_id in enumerate(involved_alert_ids, 1)}
        involved_alert_hashes_dict = {"involved_alert_hashes_" + str(i): alert_id for i, alert_id in enumerate(involved_alert_hashes, 1)}
        meta_data = {**attacker_address_md_dict, **start_date_dict, **end_date_dict, **involved_addresses_dict, **involved_alert_ids_dict, **involved_alert_hashes_dict}

        labels = []
        confidence = CONFIDENCE_MAPPINGS[alert_id]
        if alert_id in ["SCAM-DETECTOR-ICE-PHISHING", 'SCAM-DETECTOR-FRAUDULENT-NFT-ORDER',' SCAM-DETECTOR-1', 'SCAM-DETECTOR-ADDRESS-POISONER', 'SCAM-DETECTOR-ADDRESS-POISONING', 'SCAM-DETECTOR-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-WASH-TRADE', 'SCAM-DETECTOR-HARD-RUG-PULL', 'SCAM-DETECTOR-SOFT-RUG-PULL', 'SCAM-DETECTOR-RAKE-TOKEN', 'SCAM-DETECTOR-SLEEP-MINTING']:
            for scammer_address in scammer_addresses.split(","):
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': "scammer-eoa",
                    'entity': scammer_address,
                    'confidence': confidence,
                    'metadata': {
                        'alert_ids': alert_id,
                        'chain_id': chain_id,
                        'base_bot_alert_ids': ','.join(list(involved_alert_ids)),
                        'base_bot_alert_hashes': ','.join(list(involved_alert_hashes)),
                        'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                        'bot_version': Utils.get_bot_version()
                    }
                }))

                # perf optimization; these are the poisoned addresses that usually have no activity, but the POISONER are still being checked
                if 'POISONING' not in alert_id:
                    # get all deployed contracts by EOA and add label for those using etherscan or allium
                    logging.info(f"Getting contracts for scammer address {scammer_address}")
                    try:
                        contracts = block_chain_indexer.get_contracts(scammer_address, chain_id)
                        logging.info(f"Got {len(contracts)} contracts for scammer address {scammer_address}")
                        for contract in contracts:
                            if contract in scammer_contract_addresses:
                                labels.append(Label({
                                    'entityType': EntityType.Address,
                                    'label': "scammer-contract",
                                    'entity': contract,
                                    'confidence': confidence*0.9,
                                    'metadata': {
                                        'alert_ids': alert_id,
                                        'chain_id': chain_id,
                                        'base_bot_alert_ids': ','.join(list(involved_alert_ids)),
                                        'base_bot_alert_hashes': ','.join(list(involved_alert_hashes)),
                                        'scammer': scammer_address,
                                        'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id)
                                    }
                                }))
                            else:
                                labels.append(Label({
                                    'entityType': EntityType.Address,
                                    'label': "scammer-contract",
                                    'entity': contract,
                                    'confidence': confidence*0.9,
                                    'metadata': {
                                        'alert_ids': "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT",
                                        'chain_id': chain_id,
                                        'base_bot_alert_ids': ','.join(list(involved_alert_ids)),
                                        'base_bot_alert_hashes': ','.join(list(involved_alert_hashes)),
                                        'deployer_info': f"Deployer {scammer_address} involved in {alert_id} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                                        'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                                        'bot_version': Utils.get_bot_version()
                                    }
                                }))
                    except Exception as e:
                        logging.warning(f"Error getting contracts for scammer address {scammer_address}: {e}")
                        
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
    def alert_FP(w3, addresses: str) -> Finding:

        labels = []
        for address in addresses.split(","):
            label = "scammer-contract" if Utils.is_contract(w3, address) else "scammer-eoa"
            labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': label,
                    'entity': address,
                    'confidence': 0.99,
                    'remove': "true",
                    'bot_version': Utils.get_bot_version()
                }))

        return Finding({
            'name': 'Scam detector identified an address that was incorrectly alerted on. Emitting false positive alert.',
            'description': f'{address} likely not involved in a scam (SCAM-DETECTOR-FALSE-POSITIVE)',
            'alert_id': 'SCAM-DETECTOR-FALSE-POSITIVE',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
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
                    'chain_id': chain_id,
                    'bot_version': Utils.get_bot_version()
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
                        'alert_ids': "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT",
                        'chain_id': chain_id,
                        'reported_by': reported_by,
                        'deployer_info': f"Deployer {scammer_address} involved in {'SCAM-DETECTOR-MANUAL-'+alert_id_threat_category} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                        'bot_version': Utils.get_bot_version()
                    }
                }))

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
            'description': f'{scammer_cluster} likely involved in an attack (SCAM-DETECTOR-MANUAL-{alert_id_threat_category})',
            'alert_id': "SCAM-DETECTOR-MANUAL-" + alert_id_threat_category,
            'type': FindingType.Scam,
            'severity': FindingSeverity.Critical,
            'metadata': {"reported_by": reported_by},
            'labels': labels
        })

    @staticmethod
    def scammer_contract_deployment(scammer_address: str, scammer_contract_address: str, original_alert_id: str, original_alert_hash: str, chain_id: int) -> Finding:

        alert_id = "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"
        
        if original_alert_id in ['SCAM-DETECTOR-ADDRESS-POISONER', 'SCAM-DETECTOR-ICE-PHISHING', 'SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-HARD-RUG-PULL', 'SCAM-DETECTOR-SOFT-RUG-PULL', 'SCAM-DETECTOR-RAKE-TOKEN']:
            labels = []
            confidence = CONFIDENCE_MAPPINGS[alert_id]
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "scammer-contract",
                'entity': scammer_contract_address,
                'confidence': confidence,
                'metadata': { # there is no base bot alert id as this happens from handleTx handler
                    'alert_ids': alert_id,  # "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"
                    'chain_id': chain_id,
                    'associated_scammer': scammer_address,  
                    'associated_scammer_alert_id': original_alert_id,  # SCAM-DETECTOR-* alertId of the associated scammer
                    'associated_scammer_alert_hash': original_alert_hash,
                    'deployer_info': f"Deployer {scammer_address} involved in {original_alert_id} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                    'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                    'bot_version': Utils.get_bot_version()
                }
            }))

            metadata = {}
            metadata['scammer_address'] = scammer_address
            metadata['scammer_contract_address'] = scammer_contract_address
            metadata['involved_alert_id_1'] = original_alert_id
            metadata['involved_alert_hash_1'] = original_alert_hash

            return Finding({
                'name': 'Scam detector identified a scammer EOA deploying a contract',
                'description': f'{scammer_address} deployed a contract {scammer_contract_address} ({alert_id})',
                'alert_id': alert_id,
                'type': FindingType.Scam,
                'severity': FindingSeverity.High,
                'metadata': metadata,
                'labels': labels
            })
        
    def scammer_association(block_chain_indexer, new_scammer_eoa: str, model_confidence: float, base_bot_alert_id: str, base_bot_alert_hash: str, existing_scammer_eoa: str, original_alert_id: str, original_alert_hash: str, chain_id: int) -> Finding:
        alert_id = "SCAM-DETECTOR-SCAMMER-ASSOCIATION"
    
        labels = []
        confidence = CONFIDENCE_MAPPINGS[original_alert_id]
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "scammer-eoa",
            'entity': new_scammer_eoa,
            'confidence': confidence * model_confidence,
            'metadata': {
                'alert_ids': alert_id,
                'chain_id': chain_id,
                'base_bot_alert_ids': base_bot_alert_id,
                'base_bot_alert_hashes': base_bot_alert_hash,
                'associated_scammer': existing_scammer_eoa,
                'associated_scammer_alert_ids': original_alert_id,
                'associated_scammer_alert_hashes': original_alert_hash,
                'threat_description_url': ScamDetectorFinding.get_threat_description_url(original_alert_id),
                'bot_version': Utils.get_bot_version()
            }
        }))

        # get all deployed contracts by EOA and add label for those using etherscan or allium
        try:
            contracts = block_chain_indexer.get_contracts(new_scammer_eoa, chain_id)
            for contract in contracts:
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': "scammer-contract",
                    'entity': contract,
                    'confidence': confidence * model_confidence * 0.8,
                    'metadata': {
                        'alert_ids': "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT",
                        'chain_id': chain_id,
                        'base_bot_alert_ids': base_bot_alert_id,  # alert from the label propagation bot
                        'base_bot_alert_hashes': base_bot_alert_hash, # alert from the label propagation bot
                        'associated_scammer': existing_scammer_eoa,  
                        'associated_scammer_alert_ids': original_alert_id, # SCAM-DETECTOR alert id of the original associated scammer
                        'associated_scammer_alert_hashes': original_alert_hash,
                        'deployer_info': f"Deployer {new_scammer_eoa} associated with a scammer {existing_scammer_eoa}; this contract may or may not be related to this particular scam, but was created by the scammer.",
                        'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                        'bot_version': Utils.get_bot_version()
                    }
                }))
        except Exception as e:
            logging.warning(f"Error getting contracts for scammer address {new_scammer_eoa}: {e}")

        metadata = {}
        metadata['scammer_address'] = new_scammer_eoa
        metadata['associated_scammer'] = existing_scammer_eoa
        metadata['model_confidence'] = model_confidence
        metadata['involved_alert_id_1'] = original_alert_id
        metadata['involved_alert_hash_1'] = original_alert_hash

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to scam behavior',
            'description': f'{new_scammer_eoa} is associated with scammer {existing_scammer_eoa} (SCAM-DETECTOR-SCAMMER-ASSOCIATION)',
            'alert_id': alert_id,
            'type': FindingType.Scam,
            'severity': FindingSeverity.Critical,
            'metadata': metadata,
            'labels': labels
        })