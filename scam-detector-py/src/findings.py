from operator import inv
from time import strftime
from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType, get_labels
from datetime import datetime
from typing import Optional, List
import pandas as pd
import requests
import logging
import re
import traceback
import hashlib

from src.utils import Utils
from src.constants import MODEL_NAME

class ScamDetectorFinding:

    LABEL_VERSION = "2.1.0"

    @staticmethod
    def get_threat_description_url(alert_id: str) -> str:
        url = "https://forta.org/attacks"
        if alert_id == "SCAM-DETECTOR-ICE-PHISHING" or alert_id == "SCAM-DETECTOR-METAMASK-PHISHING":
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
        elif alert_id == "SCAM-DETECTOR-IMPERSONATING-TOKEN":
            return url + "#impersonating-token"
        elif alert_id == "SCAM-DETECTOR-PRIVATE-KEY-COMPROMISE":
            return url + "#private-key-compromise"
        elif alert_id == "SCAM-DETECTOR-GAS-MINTING":
            return url + "#gas-minting"
        elif alert_id == "SCAM-DETECTOR-PIG-BUTCHERING":
            return url + "#pig-butchering"
        else:
            return url
        
    @staticmethod
    def get_threat_category(alert_id: str) -> str:
        if alert_id == "SCAM-DETECTOR-ICE-PHISHING" or alert_id == "SCAM-DETECTOR-METAMASK-PHISHING":
            return "ice-phishing"
        elif alert_id == "SCAM-DETECTOR-FRAUDULENT-NFT-ORDER":
            return "fraudulent-nft-order"
        elif alert_id == "SCAM-DETECTOR-ADDRESS-POISONING":
            return "address-poisoning"
        elif alert_id == "SCAM-DETECTOR-ADDRESS-POISONER":
            return "address-poisoner"
        elif alert_id == "SCAM-DETECTOR-NATIVE-ICE-PHISHING":
            return "native-ice-phishing"
        elif alert_id == "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING":
            return "native-ice-phishing-social-engineering"
        elif alert_id == "SCAM-DETECTOR-WASH-TRADE":
            return "wash-trading"
        elif alert_id == "SCAM-DETECTOR-SLEEP-MINTING":
            return "sleep-minting"
        elif alert_id == "SCAM-DETECTOR-HARD-RUG-PULL":
            return "hard-rug-pull"
        elif alert_id == "SCAM-DETECTOR-SOFT-RUG-PULL":
            return "soft-rug-pull"
        elif alert_id == "SCAM-DETECTOR-RAKE-TOKEN":
            return "rake-token"
        elif alert_id == "SCAM-DETECTOR-IMPERSONATING-TOKEN":
            return "impersonating-token"
        elif alert_id == "SCAM-DETECTOR-SIMILAR-CONTRACT":
            return "similar-contract"
        elif alert_id == "SCAM-DETECTOR-SCAMMER-ASSOCIATION":
            return "scammer-association"
        elif alert_id == "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT":
            return "scammer-deployed-contract"
        elif alert_id == "SCAM-DETECTOR-1":
            return "attack-stages"
        elif alert_id == "SCAM-DETECTOR-SLEEP-DROP":
            return "sleepdrop"
        elif alert_id == "SCAM-DETECTOR-PRIVATE-KEY-COMPROMISE":
            return "private-key-compromise"
        elif alert_id == "SCAM-DETECTOR-PIG-BUTCHERING":
            return "pig-butchering"
        elif alert_id == "SCAM-DETECTOR-GAS-MINTING":
            return "gas-minting"
        elif alert_id == "SCAM-DETECTOR-UNKNOWN":
            return "unknown"
        else:
            return ""

    @staticmethod
    def alert_similar_contract(block_chain_indexer, forta_explorer, base_bot_alert_id: str, base_bot_alert_hash: str, metadata: dict, chain_id:int) -> Optional[Finding]:

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

        alert_id = "SCAM-DETECTOR-SIMILAR-CONTRACT"  # only used in context of alerts; in context of labels we talk about threat-categories

        original_threat_categories = set()  # scammer-eoa/* threat categories of the original scammer
        source_id = '0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8' if Utils.is_beta() else '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23'
        df_labels = forta_explorer.get_labels(source_id, datetime(2023,1,1), datetime.now(), entity = existing_scammer_contract_address.lower())

        for index, row in df_labels.iterrows():
            if row['metadata'] is not None and "address_type" in row['metadata'].keys() and "threat_category" in row['metadata'].keys() and row['metadata']['address_type'] == 'contract':
                original_threat_category = row['metadata']['threat_category']
                original_threat_categories.add(original_threat_category)
                logging.info(f"retrieved original threat category for label {existing_scammer_contract_address.lower()}: {original_threat_category}")
        

        if len(original_threat_categories.intersection(set(['address-poisoner', 'native-ice-phishing-social-engineering', 'hard-rug-pull', 'soft-rug-pull', 'rake-token', 'impersonating-token'])))>0:
            labels = []
            threat_category = ScamDetectorFinding.get_threat_category(alert_id)
            confidence = Utils.get_confidence_value(threat_category)
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': 'scammer',
                'entity': scammer_address,
                'confidence': confidence,
                'metadata': {
                    'address_type': 'EOA',
                    'chain_id': chain_id,
                    'base_bot_alert_ids': base_bot_alert_id,  # base bot alert id: contract similarity alert id
                    'base_bot_alert_hashes': base_bot_alert_hash,
                    'associated_scammer_contract': existing_scammer_contract_address,
                    'associated_scammer_threat_categories': ','.join(original_threat_categories),
                    'associated_scammer_alert_hashes': alert_hash,
                    'deployer_info': f"Deployer {scammer_address} deployed a contract {scammer_contract_address} that is similar to a contract {existing_scammer_contract_address} deployed by a known scammer {existing_scammer_address} involved in {','.join(original_threat_categories)} scam (alert hash: {alert_hash}).",
                    'threat_category': threat_category,
                    'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                    'bot_version': Utils.get_bot_version(),
                    'label_version': ScamDetectorFinding.LABEL_VERSION,
                    'logic': 'propagation'
                }
            }))

            common_scammer_contract_label_properties = {
                'entityType': EntityType.Address,
                'entity': scammer_contract_address,
                'confidence': confidence,
                'metadata': {
                    'address_type': 'contract',
                    'chain_id': chain_id,
                    'base_bot_alert_ids': base_bot_alert_id,  # base bot alert id: contract similarity alert id
                    'base_bot_alert_hashes': base_bot_alert_hash,
                    'associated_scammer_contract': existing_scammer_contract_address,
                    'associated_scammer_threat_categories': ','.join(original_threat_categories),
                    'associated_scammer_alert_hashes': alert_hash,
                    'deployer_info': f"Deployer {scammer_address} deployed a contract {scammer_contract_address} that is similar to a contract {existing_scammer_contract_address} deployed by a known scammer {existing_scammer_address} involved in {','.join(original_threat_categories)} scam (alert hash: {alert_hash}); this contract may or may not be related to this particular scam, but was created by the scammer.",
                    'threat_category': threat_category,
                    'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                    'bot_version': Utils.get_bot_version(),
                    'label_version': ScamDetectorFinding.LABEL_VERSION,
                    'logic': 'propagation'
                }
            }

            labels.append(Label({
                'label': 'scammer',
                **common_scammer_contract_label_properties
            }))

            labels.append(Label({
                'label': 'similar-contract',
                **common_scammer_contract_label_properties
            }))

            labels.append(Label({
                'entityType': EntityType.Address,
                'label': 'scammer',
                'entity': scammer_contract_address,
                'confidence': confidence,
                'metadata': {
                    'address_type': 'contract',
                    'chain_id': chain_id,
                    'base_bot_alert_ids': base_bot_alert_id,  # base bot alert id: contract similarity alert id
                    'base_bot_alert_hashes': base_bot_alert_hash,
                    'associated_scammer_contract': existing_scammer_contract_address,
                    'associated_scammer_threat_categories': ','.join(original_threat_categories),
                    'associated_scammer_alert_hashes': alert_hash,
                    'deployer_info': f"Deployer {scammer_address} deployed a contract {scammer_contract_address} that is similar to a contract {existing_scammer_contract_address} deployed by a known scammer {existing_scammer_address} involved in {','.join(original_threat_categories)} scam (alert hash: {alert_hash}); this contract may or may not be related to this particular scam, but was created by the scammer.",
                    'threat_category': threat_category,
                    'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                    'bot_version': Utils.get_bot_version(),
                    'label_version': ScamDetectorFinding.LABEL_VERSION,
                    'logic': 'propagation'
                }
            }))

            # get all deployed contracts by EOA and add label for those using etherscan or allium
            try:
                contracts = block_chain_indexer.get_contracts(scammer_address, chain_id)
                for contract in contracts:
                    labels.append(Label({
                        'entityType': EntityType.Address,
                        'label': 'scammer',
                        'entity': contract,
                        'confidence': confidence * 0.8,
                        'metadata': {
                            'address_type': 'contract',
                            'chain_id': chain_id,
                            'base_bot_alert_ids': base_bot_alert_id,  # base bot alert id: contract similarity alert id
                            'base_bot_alert_hashes': base_bot_alert_hash,
                            'associated_scammer_contract': existing_scammer_contract_address,
                            'associated_scammer_threat_categories': ','.join(original_threat_categories),
                            'associated_scammer_alert_hashes': alert_hash,
                            'deployer_info': f"Deployer {scammer_address} involved in {','.join(original_threat_categories)} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                            'threat_category': ScamDetectorFinding.get_threat_category("SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"),
                            'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                            'bot_version': Utils.get_bot_version(),
                            'label_version': ScamDetectorFinding.LABEL_VERSION,
                            'logic': 'propagation'
                        }
                    }))
            except Exception as e:
                logging.warning(f"Error getting contracts for scammer address {scammer_address}: {e}")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "findings.alert_similar_contract", traceback.format_exc()))

            metadata = {}
            metadata['scammer_address'] = scammer_address
            metadata['scammer_contract_address'] = scammer_contract_address
            metadata['existing_scammer_address'] = existing_scammer_address
            metadata['existing_scammer_contract_address'] = existing_scammer_contract_address
            metadata['similarity_score'] = similarity_score
            metadata['involved_threat_categories'] = ','.join(original_threat_categories)
            metadata['involved_alert_hash_1'] = alert_hash

            return Finding({
                'name': 'Scam detector identified an EOA with past alerts mapping to scam behavior',
                'description': f'{scammer_address} likely involved in a scam ({alert_id}, propagation)',
                'alert_id': alert_id,
                'type': FindingType.Scam,
                'severity': FindingSeverity.Critical,
                'metadata': metadata,
                'labels': labels
            })
        
        else:
            return None
        
    @staticmethod
    def get_url(metadata:dict) -> str:
        url = metadata['URL'] if 'URL' in metadata.keys() else metadata['url'] if 'url' in metadata.keys() else metadata['Url'] if 'Url' in metadata.keys() else ""
        if url == "":
            urls = metadata['urls'] if 'urls' in metadata.keys() else ""
            if urls != "":
                for u in re.findall(r"(?:(?:https?|ftp)://)?[\w\-]+(?:\.[\w\-]+)+[\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#]", urls):
                    url = u
                    break
        return url


    @staticmethod
    def scam_finding(block_chain_indexer, forta_explorer, scammer_addresses: str, start_date: datetime, end_date: datetime, scammer_contract_addresses: set, involved_addresses: set, involved_alert_ids: set, alert_id: str, involved_alert_hashes: set, metadata: dict, chain_id: int, logic: str, score = 0.0, feature_vector = None) -> Finding:
        global MODEL_NAME
        
        feature_vector_str = ""
        if feature_vector is not None:
            for i, row in feature_vector.iterrows():
                for col in feature_vector.columns:
                    feature_vector_str += f"{row[col]},"
        
        logging.info(f"Feature vector: {feature_vector_str}")
        logging.info(f"Model name: {MODEL_NAME}")
        
        url = ScamDetectorFinding.get_url(metadata)
        url_scan_url = metadata['detail'] if ('detail' in metadata.keys() and 'URL' in metadata.keys()) else metadata['reportUrl'] if ('reportUrl' in metadata.keys() and ('type' in metadata.keys() and metadata['type'].upper()=='URL')) else metadata['report_url'] if ('report_url' in metadata.keys() and ('type' in metadata.keys() and metadata['type'].upper()=='URL')) else ""

        involved_addresses = list(involved_addresses)[0:10] if involved_addresses is not None else []
        involved_alert_hashes = sorted(list(involved_alert_hashes)[0:10])

        attacker_address_md_dict = {"scammer_addresses": scammer_addresses}
        start_date_dict = {"start_date": start_date.strftime("%Y-%m-%d")}
        end_date_dict = {"end_date": end_date.strftime("%Y-%m-%d")}
        involved_addresses_dict = {"involved_addresses_" + str(i): address for i, address in enumerate(involved_addresses, 1)}
        involved_alert_ids_dict = {"involved_alert_id_" + str(i): alert_id for i, alert_id in enumerate(involved_alert_ids, 1)}
        involved_alert_hashes_dict = {"involved_alert_hashes_" + str(i): alert_id for i, alert_id in enumerate(involved_alert_hashes, 1)}
        logic_dict = {"logic": logic}
        url_scan_url_dict = {"url_scan_url": url_scan_url}


        labels = []
        threat_category = ScamDetectorFinding.get_threat_category(alert_id)
        confidence = Utils.get_confidence_value(threat_category)
        if logic == "ml" and score != 0.0:
            confidence = score
        elif metadata is not None and 'model_score' in metadata.keys():
            confidence = metadata['model_score']

        confidence_dict = {"confidence": confidence}
        feature_vector_dict = {"feature_vector": feature_vector_str}
        model_name_dict = {"model_name": MODEL_NAME}

        if alert_id in ["SCAM-DETECTOR-IMPERSONATING-TOKEN", "SCAM-DETECTOR-PRIVATE-KEY-COMPROMISE", "SCAM-DETECTOR-ICE-PHISHING", 'SCAM-DETECTOR-FRAUDULENT-NFT-ORDER',' SCAM-DETECTOR-1', 'SCAM-DETECTOR-ADDRESS-POISONER', 'SCAM-DETECTOR-ADDRESS-POISONING', 'SCAM-DETECTOR-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING', 'SCAM-DETECTOR-WASH-TRADE', 'SCAM-DETECTOR-HARD-RUG-PULL', 'SCAM-DETECTOR-SOFT-RUG-PULL', 'SCAM-DETECTOR-RAKE-TOKEN', 'SCAM-DETECTOR-SLEEP-MINTING', 'SCAM-DETECTOR-UNKNOWN', 'SCAM-DETECTOR-PIG-BUTCHERING', 'SCAM-DETECTOR-SLEEP-DROP', 'SCAM-DETECTOR-PRIVATE-KEY-COMPROMISE', 'SCAM-DETECTOR-GAS-MINTING']:
            if scammer_addresses != '':
                for scammer_address in scammer_addresses.split(","):
                    labels.append(Label({
                        'entityType': EntityType.Address,
                        'label': 'scammer',
                        'entity': scammer_address,
                        'confidence': confidence,
                        'metadata': {
                            'address_type': 'EOA',
                            'chain_id': chain_id,
                            'base_bot_alert_ids': ','.join(sorted(list(involved_alert_ids))),
                            'base_bot_alert_hashes': ','.join(sorted(list(involved_alert_hashes))),
                            'threat_category': threat_category,
                            'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                            'bot_version': Utils.get_bot_version(),
                            'label_version': ScamDetectorFinding.LABEL_VERSION,
                            'feature_vector': feature_vector_str,
                            'model_name': MODEL_NAME,
                            'logic': logic
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
                                        'label': 'scammer',
                                        'entity': contract,
                                        'confidence': confidence*0.9,
                                        'metadata': {
                                            'address_type': 'contract',
                                            'chain_id': chain_id,
                                            'base_bot_alert_ids': ','.join(sorted(list(involved_alert_ids))),
                                            'base_bot_alert_hashes': ','.join(sorted(list(involved_alert_hashes))),
                                            'deployer_info': f"Deployer {scammer_address} involved in {alert_id} scam; this contract has been associated with this scam.",
                                            'threat_category': threat_category,
                                            'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                                            'bot_version': Utils.get_bot_version(),
                                            'label_version': ScamDetectorFinding.LABEL_VERSION,
                                            'feature_vector': feature_vector_str,
                                            'model_name': MODEL_NAME,
                                            'logic': logic
                                        }
                                    }))
                                else:
                                    labels.append(Label({
                                        'entityType': EntityType.Address,
                                        'label': 'scammer',
                                        'entity': contract,
                                        'confidence': confidence*0.9,
                                        'metadata': {
                                            'address_type': 'contract',
                                            'chain_id': chain_id,
                                            'base_bot_alert_ids': ','.join(sorted(list(involved_alert_ids))),
                                            'base_bot_alert_hashes': ','.join(sorted(list(involved_alert_hashes))),
                                            'deployer_info': f"Deployer {scammer_address} involved in {alert_id} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                                            'threat_category': ScamDetectorFinding.get_threat_category("SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"),
                                            'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                                            'bot_version': Utils.get_bot_version(),
                                            'label_version': ScamDetectorFinding.LABEL_VERSION,
                                            'logic': 'propagation'
                                        }
                                    }))
                        except Exception as e:
                            logging.warning(f"Error getting contracts for scammer address {scammer_address}: {e}")
                            Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "findings.scam_finding", traceback.format_exc()))

                    
            if url != "":
                labels.append(Label({
                    'entityType': EntityType.Url,
                    'label': 'scammer',
                    'entity': url,
                    'confidence': confidence,
                    'metadata': {
                        'chain_id': chain_id,
                        'base_bot_alert_ids': ','.join(sorted(list(involved_alert_ids))),
                        'base_bot_alert_hashes': ','.join(sorted(list(involved_alert_hashes))),
                        'threat_category': threat_category,
                        'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                        'bot_version': Utils.get_bot_version(),
                        'label_version': ScamDetectorFinding.LABEL_VERSION,
                        'feature_vector': feature_vector_str,
                        'model_name': MODEL_NAME,
                        'logic': logic,
                        'source_url_scan_url': url_scan_url
                    }
                }))
                    

        findings_metadata = {**attacker_address_md_dict, **start_date_dict, **end_date_dict, **involved_addresses_dict, **involved_alert_ids_dict, **involved_alert_hashes_dict, **logic_dict, **confidence_dict, **feature_vector_dict, **model_name_dict, **url_scan_url_dict}
      
        description = f'{scammer_addresses} likely involved in a scam ({alert_id}, {logic})'
        name = 'Scam detector identified an EOA with past alerts mapping to scam behavior'
        if scammer_addresses != "" and url != "":
            description = f'{scammer_addresses} (on URL {url}) likely involved in a scam ({alert_id}, {logic})'
        if scammer_addresses == "" and url != "":
            name = 'Scam detector identified an URL with past alerts mapping to scam behavior'
            description = f'URL {url} likely involved in a scam ({alert_id}, {logic})'

        unique_key = hashlib.sha256(f'{scammer_addresses},{url},{alert_id},{logic}'.encode()).hexdigest()
        logging.info(f'Unique key of {scammer_addresses},{url},{alert_id},{logic}: {unique_key}')

        return Finding({
            'name': name,
            'description': description,
            'alert_id': alert_id,
            'type': FindingType.Scam,
            'severity': FindingSeverity.Critical,
            'metadata': findings_metadata,
            'unique_key': unique_key,
            'labels': labels
        })

    @staticmethod
    def alert_FP(w3, address: str, label: str, metadata: tuple) -> Finding:

        #metadata is a tuple and needs to convert to dict
        metadata_dict = {}
        for pair in metadata:
            key = pair.split("=")[0]
            value = pair.split("=")[1]
            metadata_dict[key] = value

        labels = []
        labels.append(Label({
                'entityType': EntityType.Address,
                'label': label,
                'entity': address,
                'confidence': 0.99,
                'remove': "true",
                'metadata': metadata_dict

            }))

        return Finding({
            'name': 'Scam detector identified an address that was incorrectly alerted on. Emitting false positive alert.',
            'description': f'{address} likely not involved in a scam (SCAM-DETECTOR-FALSE-POSITIVE, manual)',
            'alert_id': 'SCAM-DETECTOR-FALSE-POSITIVE',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {},
            'labels': labels
        })

    @staticmethod
    def alert_etherscan_likely_FP(address: str, etherscan_labels: List[str], etherscan_nametag: str) -> Finding:
       
        labels = [
            Label({
                'entityType': EntityType.Address,
                'label': 'benign',
                'entity': address,
                'confidence': 0.99,
                })
            ]
        
        return Finding({
            'name': 'Scam detector identified an address that would likely be incorrectly alerted on. Emitting informative alert.',
            'description': f'{address} likely not involved in a scam (SCAM-DETECTOR-ETHERSCAN-FP-MITIGATION, manual)',
            'alert_id': 'SCAM-DETECTOR-ETHERSCAN-FP-MITIGATION',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {
                'benign_address': address,
                'etherscan_labels': ', '.join(etherscan_labels),
                'etherscan_nametag': etherscan_nametag
            },
            'labels': labels
        })

    @staticmethod
    def scam_finding_manual(block_chain_indexer, forta_explorer, entity_type: str, entities: str, threat_category: str, reported_by: str, chain_id: int, comment:str = '', initial_metamask_list_consumption: bool = False) -> Finding:
        label_doesnt_exist = False
        
        labels = []

        alert_id_threat_category = threat_category.upper().replace(" ", "-")


        for entity in entities.split(","):
            source_id = '0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8' if Utils.is_beta() else '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23'
            df_labels = forta_explorer.get_labels(source_id, datetime(2023,1,1), datetime.now(), entity = entity.lower()) if not initial_metamask_list_consumption else pd.DataFrame()
            if df_labels.empty:
                label_doesnt_exist = True
            
                labels.append(Label({
                    'entityType': EntityType.Address if entity_type == "Address" else EntityType.Url,
                    'label': 'scammer',
                    'entity': entity,
                    'confidence': 1,
                    'metadata': {
                        'address_type': 'EOA' if entity_type == "Address" else '',
                        'chain_id': chain_id,
                        'reported_by': reported_by,
                        'threat_category': ScamDetectorFinding.get_threat_category("SCAM-DETECTOR-"+alert_id_threat_category),
                        'bot_version': Utils.get_bot_version(),
                        'label_version': ScamDetectorFinding.LABEL_VERSION,
                        'logic': 'manual',
                        'comment': comment
                    }
                }))
                # get all deployed contracts by EOA and add label for those using etherscan or allium
                if entity_type == "Address":
                    contracts = block_chain_indexer.get_contracts(entity, chain_id)
                    for contract in contracts:
                        labels.append(Label({
                            'entityType': EntityType.Address,
                            'label': 'scammer',
                            'entity': contract,
                            'confidence': 1,
                            'metadata': {
                                'address_type': 'contract',
                                'chain_id': chain_id,
                                'reported_by': reported_by,
                                'deployer_info': f"Deployer {entity} involved in {'SCAM-DETECTOR-MANUAL-'+alert_id_threat_category} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                                'threat_category': ScamDetectorFinding.get_threat_category("SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"),
                                'bot_version': Utils.get_bot_version(),
                                'label_version': ScamDetectorFinding.LABEL_VERSION,
                                'logic': 'propagation',
                                'comment': comment
                            }
                        }))
            else:
                logging.info(f"Label already exists for {entity} - skipping")

        if label_doesnt_exist:
            return Finding({
                'name': 'Scam detector identified an EOA with past alerts mapping to attack behavior',
                'description': f'{entity} likely involved in an attack (SCAM-DETECTOR-MANUAL-{alert_id_threat_category}, manual)',
                'alert_id': "SCAM-DETECTOR-MANUAL-" + alert_id_threat_category,
                'type': FindingType.Scam,
                'severity': FindingSeverity.Critical,
                'metadata': {"reported_by": reported_by, 'comment': comment},
                'labels': labels
            })
       

    @staticmethod
    def scammer_contract_deployment(scammer_address: str, scammer_contract_address: str, original_threat_category: str, original_alert_hash: str, chain_id: int) -> Finding:

        alert_id = "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"
        if original_threat_category in ['address-poisoner', 'ice-phishing', 'native-ice-phishing-social-engineering', 'hard-rug-pull', 'soft-rug-pull', 'rake-token', 'impersonating-token'] or original_threat_category == "unknown":  # 2nd check for when threat category wasnt included in the label, but was rather part of metadata; this changed with 0.2.2
            labels = []
            threat_category = ScamDetectorFinding.get_threat_category("SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT")
            confidence = Utils.get_confidence_value(threat_category)
            common_label_properties = {
                'entityType': EntityType.Address,                
                'entity': scammer_contract_address,
                'confidence': confidence,
                'metadata': { # there is no base bot alert id as this happens from handleTx handler
                    'address_type': 'contract',
                    'chain_id': chain_id,
                    'associated_scammer': scammer_address,  
                    'associated_scammer_threat_categories': original_threat_category,  
                    'associated_scammer_alert_hashes': original_alert_hash,
                    'deployer_info': f"Deployer {scammer_address} involved in {original_threat_category} scam; this contract may or may not be related to this particular scam, but was created by the scammer.",
                    'threat_category': ScamDetectorFinding.get_threat_category("SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"),
                    'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                    'bot_version': Utils.get_bot_version(),
                    'label_version': ScamDetectorFinding.LABEL_VERSION,
                    'logic': 'propagation'
                }
            }
            labels.append(Label({                
                'label': 'scammer',
                **common_label_properties
            }))
            labels.append(Label({                
                'label': 'scammer-association',
                **common_label_properties
            }))

            metadata = {}
            metadata['scammer_address'] = scammer_address
            metadata['scammer_contract_address'] = scammer_contract_address
            metadata['involved_threat_category'] = original_threat_category
            metadata['involved_alert_hash_1'] = original_alert_hash

            return Finding({
                'name': 'Scam detector identified a scammer EOA deploying a contract',
                'description': f'{scammer_address} deployed a contract {scammer_contract_address} ({alert_id}, propagation)',
                'alert_id': alert_id,
                'type': FindingType.Scam,
                'severity': FindingSeverity.Critical,
                'metadata': metadata,
                'labels': labels
            })
        
    def scammer_association(block_chain_indexer, forta_explorer, new_scammer_eoa: str, model_confidence: float, base_bot_alert_id: str, base_bot_alert_hash: str, existing_scammer_eoa: str, original_alert_id: str, original_alert_hash: str, chain_id: int) -> Finding:
        alert_id = "SCAM-DETECTOR-SCAMMER-ASSOCIATION"
    
        original_threat_category = ScamDetectorFinding.get_threat_category(original_alert_id)

        labels = []
        confidence = Utils.get_confidence_value(original_threat_category)
        common_eoa_label_properties = {
            'entityType': EntityType.Address,
            'entity': new_scammer_eoa,
            'confidence': confidence * model_confidence,
            'metadata': {
                'address_type': 'EOA',
                'chain_id': chain_id,
                'base_bot_alert_ids': base_bot_alert_id,
                'base_bot_alert_hashes': base_bot_alert_hash,
                'associated_scammer': existing_scammer_eoa,
                'associated_scammer_threat_categories': original_threat_category,
                'associated_scammer_alert_hashes': original_alert_hash,
                'threat_category': ScamDetectorFinding.get_threat_category(alert_id),
                'threat_description_url': original_threat_category,
                'bot_version': Utils.get_bot_version(),
                'label_version': ScamDetectorFinding.LABEL_VERSION,
                'logic': 'propagation'
            }
        }
        labels.append(Label({
            'label': 'scammer',
            **common_eoa_label_properties
        }))

        labels.append(Label({
            'label': 'scammer-association',
            **common_eoa_label_properties
        }))

        # get all deployed contracts by EOA and add label for those using etherscan or allium
        try:
            contracts = block_chain_indexer.get_contracts(new_scammer_eoa, chain_id)
            common_contract_label_properties = {
                    'entityType': EntityType.Address,
                    'confidence': confidence * model_confidence * 0.8,
                    'metadata': {
                        'address_type': 'contract',
                        'chain_id': chain_id,
                        'base_bot_alert_ids': base_bot_alert_id,  # alert from the label propagation bot
                        'base_bot_alert_hashes': base_bot_alert_hash,  # alert from the label propagation bot
                        'associated_scammer': existing_scammer_eoa, 
                        'associated_scammer_threat_categories': original_threat_category,  # SCAM-DETECTOR threat category of the original associated scammer, e.g. ice-phishing
                        'associated_scammer_alert_hashes': original_alert_hash,
                        'deployer_info': f"Deployer {new_scammer_eoa} associated with a scammer {existing_scammer_eoa}; this contract may or may not be related to this particular scam, but was created by the scammer.",
                        'threat_category': ScamDetectorFinding.get_threat_category("SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"),
                        'threat_description_url': ScamDetectorFinding.get_threat_description_url(alert_id),
                        'bot_version': Utils.get_bot_version(),
                        'label_version': ScamDetectorFinding.LABEL_VERSION,
                        'logic': 'propagation'
                    }
                }
            for contract in contracts:
                labels.append(Label({                    
                    'label': 'scammer',
                    'entity': contract,
                    **common_contract_label_properties
                }))
                labels.append(Label({                    
                    'label': 'scammer-association',
                    'entity': contract,
                    **common_contract_label_properties
                }))
        except Exception as e:
            logging.warning(f"Error getting contracts for scammer address {new_scammer_eoa}: {e}")
            Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "findings.scammer_association", traceback.format_exc()))


        metadata = {}
        metadata['scammer_address'] = new_scammer_eoa
        metadata['associated_scammer'] = existing_scammer_eoa
        metadata['model_confidence'] = model_confidence
        metadata['involved_alert_id_1'] = original_alert_id
        metadata['involved_alert_hash_1'] = original_alert_hash

        return Finding({
            'name': 'Scam detector identified an EOA with past alerts mapping to scam behavior',
            'description': f'{new_scammer_eoa} is associated with scammer {existing_scammer_eoa} (SCAM-DETECTOR-SCAMMER-ASSOCIATION, propagation)',
            'alert_id': alert_id,
            'type': FindingType.Scam,
            'severity': FindingSeverity.Critical,
            'metadata': metadata,
            'labels': labels
        })