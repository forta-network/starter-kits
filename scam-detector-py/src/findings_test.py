from datetime import datetime
from web3_mock import EOA_ADDRESS_LARGE_TX, EOA_ADDRESS_SMALL_TX, CONTRACT, FUTURE_CONTRACT_TO_BE_DEPLOYED_BY_EOA_LARGE_TX, Web3Mock, CONTRACT2
from forta_agent import FindingSeverity, FindingType, EntityType
from blockchain_indexer_mock import BlockChainIndexerMock
from forta_explorer_mock import FortaExplorerMock
import pandas as pd
import hashlib

from findings import ScamDetectorFinding
from utils import Utils


forta_explorer = FortaExplorerMock()
block_chain_indexer = BlockChainIndexerMock()
w3 = Web3Mock()


class TestScamFindings:

    def test_get_threat_description_url(self):
        assert ScamDetectorFinding.get_threat_description_url("SCAM-DETECTOR-ICE-PHISHING") == "https://forta.org/attacks#ice-phishing"

    def test_scam_finding_no_url(self):
        start_date = datetime(2021, 1, 1)
        end_date = datetime(2021, 1, 2)
        involved_addresses = [EOA_ADDRESS_SMALL_TX, CONTRACT]
        involved_alerts = ["ICE-PHISHING"]
        alert_id = "SCAM-DETECTOR-ICE-PHISHING"
        hashes = ["0xabc"]
        chain_id = 1
        scammer_contract_addresses = { CONTRACT }
        metadata = {}

        finding = ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, EOA_ADDRESS_SMALL_TX, start_date, end_date, scammer_contract_addresses, involved_addresses, involved_alerts, alert_id, hashes, metadata, chain_id, "passthrough")
        assert finding.alert_id == alert_id
        assert finding.severity == FindingSeverity.Critical
        assert finding.type == FindingType.Scam
        assert finding.name == f'Scam detector identified an EOA with past alerts mapping to scam behavior'
        assert finding.description == f"{EOA_ADDRESS_SMALL_TX} likely involved in a scam ({alert_id}, passthrough)"
        assert finding.metadata is not None
        assert finding.labels is not None
        assert finding.metadata["start_date"] == "2021-01-01"
        assert finding.metadata["end_date"] == "2021-01-02"
        assert finding.metadata["involved_addresses_1"] == EOA_ADDRESS_SMALL_TX
        assert finding.metadata["involved_addresses_2"] == CONTRACT
        assert finding.metadata["involved_alert_id_1"] == "ICE-PHISHING"
        assert finding.metadata["involved_alert_hashes_1"] == "0xabc"
        assert finding.metadata["scammer_addresses"] == EOA_ADDRESS_SMALL_TX
        assert finding.metadata["logic"] == "passthrough"
        assert len(finding.labels) == 2

  
        assert finding.labels[0].entity_type == EntityType.Address
        assert finding.labels[0].entity == EOA_ADDRESS_SMALL_TX
        assert finding.labels[0].label == "scammer"
        assert finding.labels[0].confidence == Utils.get_confidence_value('ice-phishing')
        assert finding.labels[0].metadata["address_type"] == "EOA"
        assert finding.labels[0].metadata["logic"] == "passthrough"
        assert finding.labels[0].metadata["threat_category"] == "ice-phishing"
        assert finding.labels[0].metadata["base_bot_alert_ids"] == "ICE-PHISHING"
        assert finding.labels[0].metadata["base_bot_alert_hashes"] == "0xabc"
        assert finding.labels[0].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)
        assert finding.labels[0].unique_key == hashlib.sha256(f'{EOA_ADDRESS_SMALL_TX},{alert_id},{chain_id}'.encode()).hexdigest()

        assert finding.labels[1].entity_type == EntityType.Address
        assert finding.labels[1].entity == CONTRACT
        assert finding.labels[1].label == "scammer"
        assert finding.labels[1].confidence == Utils.get_confidence_value('ice-phishing') * 0.9
        assert finding.labels[1].metadata["address_type"] == "contract"
        assert finding.labels[1].metadata["threat_category"] == "ice-phishing"
        assert finding.labels[1].metadata["logic"] == "passthrough"
        assert finding.labels[1].metadata["base_bot_alert_ids"] == "ICE-PHISHING"
        assert finding.labels[1].metadata["base_bot_alert_hashes"] == "0xabc"
        assert finding.labels[1].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)
        assert finding.labels[1].unique_key == hashlib.sha256(f'{CONTRACT},{alert_id},{chain_id}'.encode()).hexdigest()

    def test_scam_finding_with_url(self):
        start_date = datetime(2021, 1, 1)
        end_date = datetime(2021, 1, 2)
        involved_addresses = [EOA_ADDRESS_SMALL_TX, CONTRACT]
        involved_alerts = ["ICE-PHISHING"]
        alert_id = "SCAM-DETECTOR-ICE-PHISHING"
        hashes = ["0xabc"]
        chain_id = 1
        scammer_contract_addresses = { CONTRACT }
        metadata = {'scammer': EOA_ADDRESS_SMALL_TX, 'URL': 'withdraw-llido.com', 'detail': 'https://urlscan.io/result/1870a15b-2b37-4980-9968-ac8a01e083f9/', 'transaction': ''}
        

        finding = ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, EOA_ADDRESS_SMALL_TX, start_date, end_date, scammer_contract_addresses, involved_addresses, involved_alerts, alert_id, hashes, metadata, chain_id, "passthrough")
        assert finding.alert_id == alert_id
        assert finding.severity == FindingSeverity.Critical
        assert finding.type == FindingType.Scam
        assert finding.name == f'Scam detector identified an EOA with past alerts mapping to scam behavior'
        assert finding.description == f"{EOA_ADDRESS_SMALL_TX} (on URL withdraw-llido.com) likely involved in a scam ({alert_id}, passthrough)"
        assert finding.metadata is not None
        assert finding.labels is not None
        assert finding.metadata["start_date"] == "2021-01-01"
        assert finding.metadata["end_date"] == "2021-01-02"
        assert finding.metadata["involved_addresses_1"] == EOA_ADDRESS_SMALL_TX
        assert finding.metadata["involved_addresses_2"] == CONTRACT
        assert finding.metadata["involved_alert_id_1"] == "ICE-PHISHING"
        assert finding.metadata["involved_alert_hashes_1"] == "0xabc"
        assert finding.metadata["scammer_addresses"] == EOA_ADDRESS_SMALL_TX
        assert finding.metadata["url_scan_url"] == 'https://urlscan.io/result/1870a15b-2b37-4980-9968-ac8a01e083f9/'
        assert finding.metadata["logic"] == "passthrough"
        assert len(finding.labels) == 3

  
        assert finding.labels[0].entity_type == EntityType.Address
        assert finding.labels[0].entity == EOA_ADDRESS_SMALL_TX
        assert finding.labels[0].label == "scammer"
        assert finding.labels[0].confidence == Utils.get_confidence_value('ice-phishing')
        assert finding.labels[0].metadata["address_type"] == "EOA"
        assert finding.labels[0].metadata["logic"] == "passthrough"
        assert finding.labels[0].metadata["threat_category"] == "ice-phishing"
        assert finding.labels[0].metadata["base_bot_alert_ids"] == "ICE-PHISHING"
        assert finding.labels[0].metadata["base_bot_alert_hashes"] == "0xabc"
        assert finding.labels[0].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)

        assert finding.labels[1].entity_type == EntityType.Address
        assert finding.labels[1].entity == CONTRACT
        assert finding.labels[1].label == "scammer"
        assert finding.labels[1].confidence == Utils.get_confidence_value('ice-phishing') * 0.9
        assert finding.labels[1].metadata["address_type"] == "contract"
        assert finding.labels[1].metadata["threat_category"] == "ice-phishing"
        assert finding.labels[1].metadata["logic"] == "passthrough"
        assert finding.labels[1].metadata["base_bot_alert_ids"] == "ICE-PHISHING"
        assert finding.labels[1].metadata["base_bot_alert_hashes"] == "0xabc"
        assert finding.labels[1].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)

        assert finding.labels[2].entity_type == EntityType.Url
        assert finding.labels[2].entity == "withdraw-llido.com"
        assert finding.labels[2].label == "scammer"
        assert finding.labels[2].confidence == Utils.get_confidence_value('ice-phishing')
        assert finding.labels[2].metadata["threat_category"] == "ice-phishing"
        assert finding.labels[2].metadata["logic"] == "passthrough"
        assert finding.labels[2].metadata["base_bot_alert_ids"] == "ICE-PHISHING"
        assert finding.labels[2].metadata["base_bot_alert_hashes"] == "0xabc"
        assert finding.labels[2].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)
        assert finding.labels[2].metadata["source_url_scan_url"] == 'https://urlscan.io/result/1870a15b-2b37-4980-9968-ac8a01e083f9/'

    def test_scam_finding_only_url(self):
        start_date = datetime(2021, 1, 1)
        end_date = datetime(2021, 1, 2)
        involved_addresses = []
        involved_alerts = ["ICE-PHISHING"]
        alert_id = "SCAM-DETECTOR-ICE-PHISHING"
        hashes = ["0xabc"]
        chain_id = 1
        scammer_contract_addresses = {  }
        metadata = {'scammer': '', 'URL': 'withdraw-llido.com', 'detail': 'https://urlscan.io/result/1870a15b-2b37-4980-9968-ac8a01e083f9/', 'transaction': ''}
        

        finding = ScamDetectorFinding.scam_finding(block_chain_indexer, forta_explorer, "", start_date, end_date, scammer_contract_addresses, involved_addresses, involved_alerts, alert_id, hashes, metadata, chain_id, "passthrough")
        assert finding.alert_id == alert_id
        assert finding.severity == FindingSeverity.Critical
        assert finding.type == FindingType.Scam
        assert finding.name == f'Scam detector identified an URL with past alerts mapping to scam behavior'
        assert finding.description == f"URL withdraw-llido.com likely involved in a scam ({alert_id}, passthrough)"
        assert finding.metadata is not None
        assert finding.labels is not None
        assert finding.metadata["start_date"] == "2021-01-01"
        assert finding.metadata["end_date"] == "2021-01-02"
        assert finding.metadata["involved_alert_id_1"] == "ICE-PHISHING"
        assert finding.metadata["involved_alert_hashes_1"] == "0xabc"
        assert finding.metadata["url_scan_url"] == 'https://urlscan.io/result/1870a15b-2b37-4980-9968-ac8a01e083f9/'
        assert finding.metadata["logic"] == "passthrough"
        assert len(finding.labels) == 1

        assert finding.labels[0].entity_type == EntityType.Url
        assert finding.labels[0].entity == "withdraw-llido.com"
        assert finding.labels[0].label == "scammer"
        assert finding.labels[0].confidence == Utils.get_confidence_value('ice-phishing')
        assert finding.labels[0].metadata["threat_category"] == "ice-phishing"
        assert finding.labels[0].metadata["logic"] == "passthrough"
        assert finding.labels[0].metadata["base_bot_alert_ids"] == "ICE-PHISHING"
        assert finding.labels[0].metadata["base_bot_alert_hashes"] == "0xabc"
        assert finding.labels[0].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)
        assert finding.labels[0].metadata["source_url_scan_url"] == 'https://urlscan.io/result/1870a15b-2b37-4980-9968-ac8a01e083f9/'


        
    def test_scam_similar_contract(self):
        chain_id = 1
        metadata = {"alert_hash":"0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016",
                           "new_scammer_contract_address":"0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2",
                           "new_scammer_eoa":"0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0",
                           "scammer_contract_address":"0xe22536ac6f6a20dbb283e7f61a880993eab63313",
                           "scammer_eoa":"0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e",
                           "similarity_hash":"68e6432db785f93986a9d49b19077067f8b694612f2bc1e8ef5cd38af2c8727e",
                           "similarity_score":"0.9347575306892395"}
        base_bot_alert_id = ""
        base_bot_alert_hash = "0x8192"
        finding = ScamDetectorFinding.alert_similar_contract(block_chain_indexer, forta_explorer, base_bot_alert_id, base_bot_alert_hash, metadata, chain_id)

        assert finding is not None
        alert_id = "SCAM-DETECTOR-SIMILAR-CONTRACT"
        assert finding.alert_id == alert_id
        assert finding.severity == FindingSeverity.Critical
        assert finding.type == FindingType.Scam
        assert finding.name == f'Scam detector identified an EOA with past alerts mapping to scam behavior'
        assert finding.description == f"0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0 likely involved in a scam ({alert_id}, propagation)"
        assert finding.metadata is not None
        assert finding.labels is not None

        assert finding.metadata['scammer_address'] == "0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0"
        assert finding.metadata['scammer_contract_address'] == "0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2"
        assert finding.metadata['existing_scammer_address'] == "0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e"
        assert finding.metadata['existing_scammer_contract_address'] == "0xe22536ac6f6a20dbb283e7f61a880993eab63313"
        assert finding.metadata['similarity_score'] == "0.9347575306892395"
        assert finding.metadata['involved_threat_categories'] == "address-poisoner"
        assert finding.metadata['involved_alert_hash_1'] == "0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016"

        assert len(finding.labels) == 3

        assert finding.labels[0].entity_type == EntityType.Address
        assert finding.labels[0].entity == "0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0"
        assert finding.labels[0].label == "scammer"
        assert finding.labels[0].confidence == Utils.get_confidence_value('similar-contract')
        assert finding.labels[0].metadata["address_type"] == "EOA"
        assert finding.labels[0].metadata["logic"] == "propagation"
        assert finding.labels[0].metadata["base_bot_alert_ids"] == base_bot_alert_id
        assert finding.labels[0].metadata["base_bot_alert_hashes"] == base_bot_alert_hash
        assert finding.labels[0].metadata["deployer_info"] == f'Deployer {metadata["new_scammer_eoa"]} deployed a contract {metadata["new_scammer_contract_address"]} that is similar to a contract {metadata["scammer_contract_address"]} deployed by a known scammer {metadata["scammer_eoa"]} involved in address-poisoner scam (alert hash: {metadata["alert_hash"]}).'
        assert finding.labels[0].metadata["threat_category"] == "similar-contract"
        assert finding.labels[0].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)

        assert finding.labels[1].entity_type == EntityType.Address
        assert finding.labels[1].entity == "0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2"
        assert finding.labels[1].label == "scammer"
        assert finding.labels[1].confidence == Utils.get_confidence_value('similar-contract')
        assert finding.labels[1].metadata["address_type"] == "contract"
        assert finding.labels[1].metadata["logic"] == "propagation"
        assert finding.labels[1].metadata["base_bot_alert_ids"] == base_bot_alert_id
        assert finding.labels[1].metadata["base_bot_alert_hashes"] == base_bot_alert_hash
        assert finding.labels[1].metadata["deployer_info"] == "Deployer 0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0 deployed a contract 0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2 that is similar to a contract 0xe22536ac6f6a20dbb283e7f61a880993eab63313 deployed by a known scammer 0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e involved in address-poisoner scam (alert hash: 0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016); this contract may or may not be related to this particular scam, but was created by the scammer."
        assert finding.labels[1].metadata["threat_category"] == "similar-contract"
        assert finding.labels[1].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)

        assert finding.labels[2].entity_type == EntityType.Address
        assert finding.labels[2].entity == "0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2"
        assert finding.labels[2].label == "similar-contract"
        assert finding.labels[2].confidence == Utils.get_confidence_value('similar-contract')
        assert finding.labels[2].metadata["address_type"] == "contract"
        assert finding.labels[2].metadata["logic"] == "propagation"
        assert finding.labels[2].metadata["base_bot_alert_ids"] == base_bot_alert_id
        assert finding.labels[2].metadata["base_bot_alert_hashes"] == base_bot_alert_hash
        assert finding.labels[2].metadata["deployer_info"] == "Deployer 0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0 deployed a contract 0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2 that is similar to a contract 0xe22536ac6f6a20dbb283e7f61a880993eab63313 deployed by a known scammer 0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e involved in address-poisoner scam (alert hash: 0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016); this contract may or may not be related to this particular scam, but was created by the scammer."
        assert finding.labels[2].metadata["threat_category"] == "similar-contract"
        assert finding.labels[2].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)
        

    def test_alert_FP(self):
        finding = ScamDetectorFinding.alert_FP(w3, EOA_ADDRESS_LARGE_TX, "scammer", ("threat_category=similar-contract", "address_type=EOA", "logic=propagation"), [""])
        assert finding.alert_id == "SCAM-DETECTOR-FALSE-POSITIVE", "should be FP"
        assert finding.description == f'{EOA_ADDRESS_LARGE_TX} likely not involved in a scam (SCAM-DETECTOR-FALSE-POSITIVE, manual)', "should be FP"
        assert len(finding.labels) == 1, "should be 1"
        assert finding.labels[0].label == "scammer"
        assert finding.labels[0].remove == 'true', "should be remove"
        assert finding.labels[0].metadata["address_type"] == "EOA"
        assert finding.labels[0].metadata["threat_category"] == "similar-contract"
        assert finding.labels[0].metadata["logic"] == "propagation"

        assert finding.labels[0].entity == EOA_ADDRESS_LARGE_TX, "should be EOA_ADDRESS_LARGE_TX"

    def test_scam_finding_manual(self):
        finding = ScamDetectorFinding.scam_finding_manual(block_chain_indexer, forta_explorer, 'Address', '0xdec08cb92a506B88411da9Ba290f3694BE223caa', "ice phishing", "me http://foo.com", 1, "comment")  # this EOA did not deploy a contract
        assert finding.alert_id == "SCAM-DETECTOR-MANUAL-ICE-PHISHING", "should be SCAM-DETECTOR-MANUAL-ICE-PHISHING"
        assert finding.description == f'0xdec08cb92a506B88411da9Ba290f3694BE223caa likely involved in an attack (SCAM-DETECTOR-MANUAL-ICE-PHISHING, manual)', "should be SCAM-DETECTOR-MANUAL-ICE-PHISHING"
        assert finding.metadata['reported_by'] == "me http://foo.com", "me http://foo.com"
        assert finding.metadata["comment"] == "comment"
        assert len(finding.labels) == 1, "should be 1"  
        assert finding.labels[0].entity == '0xdec08cb92a506B88411da9Ba290f3694BE223caa', "should be EOA_ADDRESS"
        assert finding.labels[0].metadata['reported_by'] == "me http://foo.com", "me http://foo.com"
        assert finding.labels[0].label == "scammer", "should be scamme"
        assert finding.labels[0].metadata["address_type"] == "EOA"
        assert finding.labels[0].metadata["chain_id"] == 1
        assert finding.labels[0].metadata["threat_category"] == "ice-phishing"
        assert finding.labels[0].metadata["logic"] == "manual"
        assert finding.labels[0].metadata["comment"] == "comment"


    def test_scammer_contract_deployment(self):
        finding = ScamDetectorFinding.scammer_contract_deployment(EOA_ADDRESS_LARGE_TX, CONTRACT, "native-ice-phishing-social-engineering", "0xabc", 1, [FUTURE_CONTRACT_TO_BE_DEPLOYED_BY_EOA_LARGE_TX])

        assert finding is not None
        assert finding.alert_id == "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT", "should be SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"
        assert finding.description == f'{EOA_ADDRESS_LARGE_TX} deployed a contract {CONTRACT} (SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT, propagation)'
        assert len(finding.labels) == 2, "should be 2; only the deployed and the future contract as the scammer already exists"  
        assert finding.labels[0].entity == CONTRACT, "should be CONTRACT"
        assert finding.labels[0].metadata['associated_scammer'] == EOA_ADDRESS_LARGE_TX
        assert finding.labels[0].metadata['associated_scammer_threat_categories'] ==  "native-ice-phishing-social-engineering"
        assert finding.labels[0].metadata['associated_scammer_alert_hashes'] == "0xabc"
        assert finding.labels[0].metadata['deployer_info'] == f"Deployer {EOA_ADDRESS_LARGE_TX} involved in native-ice-phishing-social-engineering scam; this contract may or may not be related to this particular scam, but was created by the scammer."
        assert finding.labels[0].label == "scammer", "should be scammer"
        assert finding.labels[0].metadata["address_type"] == "contract"
        assert finding.labels[0].metadata["logic"] == "propagation"
        assert finding.labels[0].metadata["threat_category"] == "scammer-deployed-contract"
        assert finding.labels[1].entity == FUTURE_CONTRACT_TO_BE_DEPLOYED_BY_EOA_LARGE_TX, "should be FUTURE_CONTRACT_TO_BE_DEPLOYED_BY_EOA_LARGE_TX"
        assert finding.labels[1].metadata['associated_scammer'] == EOA_ADDRESS_LARGE_TX
        assert finding.labels[1].metadata['associated_scammer_threat_categories'] ==  "native-ice-phishing-social-engineering"
        assert finding.labels[1].metadata['associated_scammer_alert_hashes'] == "0xabc"
        assert finding.labels[1].metadata['deployer_info'] == f"Deployer {EOA_ADDRESS_LARGE_TX} involved in native-ice-phishing-social-engineering scam; this contract may or may not be deployed and may or may not be related to this particular scam, but would be created by the scammer."
        assert finding.labels[1].label == "scammer", "should be scammer"
        assert finding.labels[1].metadata["address_type"] == "contract"
        assert finding.labels[1].metadata["logic"] == "propagation"
        assert finding.labels[1].metadata["threat_category"] == "scammer-deployed-contract"



    def test_scammer_association(self):
        #{"central_node":"0x13549e22de184a881fe3d164612ef15f99f6d4b3",
        # "central_node_alert_hash":"0xbda39ad1c0a53555587a8bc9c9f711f0cad81fe89ef235a6d79ee905bc70526c",
        # "central_node_alert_id":"SCAM-DETECTOR-ICE-PHISHING",
        # "central_node_alert_name":"Scam detector identified an EOA with past alerts mapping to scam behavior",
        # "model_confidence":0.5,
        # "graph_statistics":"[object Object]"}
        
        new_address = EOA_ADDRESS_SMALL_TX
        existing_address = EOA_ADDRESS_LARGE_TX
        original_alert_id = "SCAM-DETECTOR-ICE-PHISHING"
        original_alert_hash = "0xbda39ad1c0a53555587a8bc9c9f711f0cad81fe89ef235a6d79ee905bc70526c"
        model_confidence = 0.5
        base_bot_alert_id = "FOO"
        base_bot_alert_hash = "0xabc"

        finding = ScamDetectorFinding.scammer_association(block_chain_indexer, forta_explorer, new_address, model_confidence, base_bot_alert_id, base_bot_alert_hash, existing_address, original_alert_id, original_alert_hash, 1)

        assert finding.alert_id == "SCAM-DETECTOR-SCAMMER-ASSOCIATION"
        assert finding.description == f'{EOA_ADDRESS_SMALL_TX} is associated with scammer {EOA_ADDRESS_LARGE_TX} (SCAM-DETECTOR-SCAMMER-ASSOCIATION, propagation)'
        assert finding.metadata['involved_alert_id_1'] == "SCAM-DETECTOR-ICE-PHISHING"
        assert finding.metadata['involved_alert_hash_1'] == original_alert_hash
        assert len(finding.labels) == 4, "should be 4"  
        assert finding.labels[0].entity == EOA_ADDRESS_SMALL_TX
        assert finding.labels[0].label == "scammer"
        assert finding.labels[0].metadata["address_type"] == "EOA"
        assert finding.labels[0].metadata["logic"] == "propagation"

        assert finding.labels[0].confidence == Utils.get_confidence_value('ice-phishing') * 0.5
        assert finding.labels[0].metadata['base_bot_alert_ids'] == base_bot_alert_id
        assert finding.labels[0].metadata['base_bot_alert_hashes'] == base_bot_alert_hash
        assert finding.labels[0].metadata['associated_scammer'] == EOA_ADDRESS_LARGE_TX
        assert finding.labels[0].metadata['associated_scammer_threat_categories'] == 'ice-phishing'
        assert finding.labels[0].metadata['associated_scammer_alert_hashes'] == original_alert_hash
        assert finding.labels[0].metadata["threat_category"] == "scammer-association"

        assert finding.labels[1].entity == EOA_ADDRESS_SMALL_TX
        assert finding.labels[1].label == "scammer-association"
        assert finding.labels[1].metadata["address_type"] == "EOA"
        assert finding.labels[1].metadata["logic"] == "propagation"

        assert finding.labels[1].confidence == Utils.get_confidence_value('ice-phishing') * 0.5
        assert finding.labels[1].metadata['base_bot_alert_ids'] == base_bot_alert_id
        assert finding.labels[1].metadata['base_bot_alert_hashes'] == base_bot_alert_hash
        assert finding.labels[1].metadata['associated_scammer'] == EOA_ADDRESS_LARGE_TX
        assert finding.labels[1].metadata['associated_scammer_threat_categories'] == 'ice-phishing'
        assert finding.labels[1].metadata['associated_scammer_alert_hashes'] == original_alert_hash
        assert finding.labels[1].metadata["threat_category"] == "scammer-association"

        assert finding.labels[2].entity == CONTRACT
        assert finding.labels[2].label == "scammer"
        assert finding.labels[2].metadata["address_type"] == "contract"
        assert finding.labels[2].metadata["logic"] == "propagation"
        assert finding.labels[2].metadata["threat_category"] == "scammer-deployed-contract"

        assert finding.labels[2].confidence == (Utils.get_confidence_value('ice-phishing') * 0.5 * 0.8)
        assert finding.labels[2].metadata['associated_scammer'] == EOA_ADDRESS_LARGE_TX
        assert finding.labels[2].metadata['associated_scammer_threat_categories'] == 'ice-phishing'
        assert finding.labels[2].metadata['associated_scammer_alert_hashes'] == original_alert_hash
        assert finding.labels[2].metadata['deployer_info'] == f"Deployer {EOA_ADDRESS_SMALL_TX} associated with a scammer {EOA_ADDRESS_LARGE_TX}; this contract may or may not be related to this particular scam, but was created by the scammer."

        assert finding.labels[3].entity == CONTRACT
        assert finding.labels[3].label == "scammer-association"
        assert finding.labels[3].metadata["address_type"] == "contract"
        assert finding.labels[3].metadata["logic"] == "propagation"
        assert finding.labels[3].metadata["threat_category"] == "scammer-deployed-contract"

        assert finding.labels[3].confidence == (Utils.get_confidence_value('ice-phishing') * 0.5 * 0.8)
        assert finding.labels[3].metadata['associated_scammer'] == EOA_ADDRESS_LARGE_TX
        assert finding.labels[3].metadata['associated_scammer_threat_categories'] == 'ice-phishing'
        assert finding.labels[3].metadata['associated_scammer_alert_hashes'] == original_alert_hash
        assert finding.labels[3].metadata['deployer_info'] == f"Deployer {EOA_ADDRESS_SMALL_TX} associated with a scammer {EOA_ADDRESS_LARGE_TX}; this contract may or may not be related to this particular scam, but was created by the scammer."
