from datetime import datetime
from web3_mock import EOA_ADDRESS_LARGE_TX, EOA_ADDRESS_SMALL_TX, CONTRACT, Web3Mock
from forta_agent import FindingSeverity, FindingType, EntityType
from blockchain_indexer_mock import BlockChainIndexerMock
import pandas as pd

from findings import ScamDetectorFinding


block_chain_indexer = BlockChainIndexerMock()
w3 = Web3Mock()


class TestScamFindings:

    def test_get_threat_description_url(self):
        assert ScamDetectorFinding.get_threat_description_url("SCAM-DETECTOR-ICE-PHISHING") == "https://forta.org/attacks#ice-phishing"

    def test_scam_finding(self):
        start_date = datetime(2021, 1, 1)
        end_date = datetime(2021, 1, 2)
        involved_addresses = [EOA_ADDRESS_SMALL_TX, CONTRACT]
        involved_alerts = ["ICE-PHISHING"]
        alert_id = "SCAM-DETECTOR-ICE-PHISHING"
        hashes = ["0xabc"]
        chain_id = 1

        finding = ScamDetectorFinding.scam_finding(block_chain_indexer, EOA_ADDRESS_SMALL_TX, start_date, end_date, involved_addresses, involved_alerts, alert_id, hashes, chain_id)
        assert finding.alert_id == alert_id
        assert finding.severity == FindingSeverity.Critical
        assert finding.type == FindingType.Scam
        assert finding.name == f'Scam detector identified an EOA with past alerts mapping to scam behavior'
        assert finding.description == f"{EOA_ADDRESS_SMALL_TX} likely involved in a scam ({alert_id})"
        assert finding.metadata is not None
        assert finding.labels is not None
        assert finding.metadata["start_date"] == "2021-01-01"
        assert finding.metadata["end_date"] == "2021-01-02"
        assert finding.metadata["involved_addresses_1"] == EOA_ADDRESS_SMALL_TX
        assert finding.metadata["involved_addresses_2"] == CONTRACT
        assert finding.metadata["involved_alert_id_1"] == "ICE-PHISHING"
        assert finding.metadata["involved_alert_hashes_1"] == "0xabc"
        assert finding.metadata["scammer_addresses"] == EOA_ADDRESS_SMALL_TX
        assert len(finding.labels) == 2

  
        assert finding.labels[0].entity_type == EntityType.Address
        assert finding.labels[0].entity == EOA_ADDRESS_SMALL_TX
        assert finding.labels[0].label == "scammer-eoa"
        assert finding.labels[0].confidence == 0.8
        assert finding.labels[0].metadata["alert_ids"] == alert_id
        assert finding.labels[0].metadata["chain_id"] == chain_id
        assert finding.labels[0].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)

        assert finding.labels[1].entity_type == EntityType.Address
        assert finding.labels[1].entity == CONTRACT
        assert finding.labels[1].label == "scammer-contract"
        assert finding.labels[1].confidence == 0.7
        assert finding.labels[1].metadata["alert_ids"] == alert_id
        assert finding.labels[1].metadata["chain_id"] == chain_id
        assert finding.labels[1].metadata["deployer"] == EOA_ADDRESS_SMALL_TX
        assert finding.labels[1].metadata["deployer_info"] == f"Deployer involved in {alert_id} scam; this contract may or may not be related to this particular scam, but was created by the scammer."
        assert finding.labels[1].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)



        
    def test_scam_similar_contract(self):
        chain_id = 1
        metadata = {"alert_hash":"0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016",
                           "new_scammer_contract_address":"0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2",
                           "new_scammer_eoa":"0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0",
                           "scammer_contract_address":"0xe22536ac6f6a20dbb283e7f61a880993eab63313",
                           "scammer_eoa":"0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e",
                           "similarity_hash":"68e6432db785f93986a9d49b19077067f8b694612f2bc1e8ef5cd38af2c8727e",
                           "similarity_score":"0.9347575306892395"}
        finding = ScamDetectorFinding.alert_similar_contract(block_chain_indexer, metadata, chain_id)

        alert_id = "SCAM-DETECTOR-SIMILAR-CONTRACT"
        assert finding.alert_id == alert_id
        assert finding.severity == FindingSeverity.Critical
        assert finding.type == FindingType.Scam
        assert finding.name == f'Scam detector identified an EOA with past alerts mapping to scam behavior'
        assert finding.description == f"0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0 likely involved in a scam ({alert_id})"
        assert finding.metadata is not None
        assert finding.labels is not None

        assert finding.metadata['scammer_address'] == "0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0"
        assert finding.metadata['scammer_contract_address'] == "0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2"
        assert finding.metadata['existing_scammer_address'] == "0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e"
        assert finding.metadata['existing_scammer_contract_address'] == "0xe22536ac6f6a20dbb283e7f61a880993eab63313"
        assert finding.metadata['similarity_score'] == "0.9347575306892395"
        assert finding.metadata['involved_alert_id_1'] == "SCAM-DETECTOR-ADDRESS-POISONER"
        assert finding.metadata['involved_alert_hash_1'] == "0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016"

        assert len(finding.labels) == 2

        assert finding.labels[0].entity_type == EntityType.Address
        assert finding.labels[0].entity == "0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0"
        assert finding.labels[0].label == "scammer-eoa"
        assert finding.labels[0].confidence == 0.7
        assert finding.labels[0].metadata["alert_ids"] == alert_id
        assert finding.labels[0].metadata["chain_id"] == chain_id
        assert finding.labels[0].metadata["similar_contract_alert_ids"] == "SCAM-DETECTOR-ADDRESS-POISONER"
        assert finding.labels[0].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)

        assert finding.labels[1].entity_type == EntityType.Address
        assert finding.labels[1].entity == "0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2"
        assert finding.labels[1].label == "scammer-contract"
        assert finding.labels[1].confidence == 0.7
        assert finding.labels[1].metadata["alert_ids"] == alert_id
        assert finding.labels[1].metadata["chain_id"] == chain_id
        assert finding.labels[1].metadata["similar_contract_alert_ids"] == "SCAM-DETECTOR-ADDRESS-POISONER"
        assert finding.labels[1].metadata["deployer"] == "0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0"
        assert finding.labels[1].metadata["deployer_info"] == f"Deployer involved in {alert_id} scam; this contract may or may not be related to this particular scam, but was created by the scammer."
        assert finding.labels[1].metadata["threat_description_url"] == ScamDetectorFinding.get_threat_description_url(alert_id)
        

    def test_alert_FP(self):
        finding = ScamDetectorFinding.alert_FP(w3, EOA_ADDRESS_LARGE_TX)
        assert finding.alert_id == "SCAM-DETECTOR-FALSE-POSITIVE", "should be FP"
        assert finding.description == f'{EOA_ADDRESS_LARGE_TX} likely not involved in a scam (SCAM-DETECTOR-FALSE-POSITIVE)', "should be FP"
        assert len(finding.labels) == 1, "should be 1"


    def test_alert_FP_cluster(self):
        finding = ScamDetectorFinding.alert_FP(w3, EOA_ADDRESS_LARGE_TX + "," + EOA_ADDRESS_SMALL_TX)
        assert finding.alert_id == "SCAM-DETECTOR-FALSE-POSITIVE", "should be FP"
        assert len(finding.labels) == 2, "should be 2"
