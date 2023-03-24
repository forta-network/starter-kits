from findings import ScamDetectorFinding
from web3_mock import EOA_ADDRESS, EOA_ADDRESS_2, CONTRACT
from blockchain_indexer_mock import BlockChainIndexerMock
import pandas as pd

block_chain_indexer = BlockChainIndexerMock()

class TestScamFindings:
    def test_scam_finding_model(self):

        feature_vector = pd.DataFrame([[0,2,5]], columns=['0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c_SEAPORT-PHISHING-TRANSFER', '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS', '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-PERMITTED-ERC20-TRANSFER'])
        alerts = [("0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c", "SEAPORT-PHISHING-TRANSFER", "hash1"),
                  ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS", "hash2"),
                  ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-PERMITTED-ERC20-TRANSFER", "hash3"),
                  ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-PERMITTED-ERC20-TRANSFER", "hash4")]
        
        finding = ScamDetectorFinding.scam_finding_model(block_chain_indexer, EOA_ADDRESS_2, 0.9, feature_vector, alerts, 1)  # this EOA did not deploy a contract
        assert finding.alert_id == "SCAM-DETECTOR-MODEL-1", "should be SCAM-DETECTOR-MODEL-1"
        assert finding.description == f'{EOA_ADDRESS_2} likely involved in an attack (SCAM-DETECTOR-MODEL-1)', "should be SCAM-DETECTOR-MODEL-1"
        assert len(finding.labels) == 1, "should be 1"
        assert finding.labels[0].entity == EOA_ADDRESS_2, "should be EOA_ADDRESS_2"
        assert finding.labels[0].metadata['alert_ids'] == "SCAM-DETECTOR-MODEL-1", "should be SCAM-DETECTOR-MODEL-1"
        assert finding.labels[0].metadata['chain_id'] == 1, "should be 1"

        assert finding.metadata['feature_vector'] == feature_vector.to_json(), "should be the same"

        base_alerts = set()
        base_alerts.add(finding.metadata['base_alert_1'])
        base_alerts.add(finding.metadata['base_alert_2'])
        base_alerts.add(finding.metadata['base_alert_3'])
        assert len(base_alerts) == 3, "should be 3"


        assert "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14,ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS,hash2" in base_alerts, "should be hash2"
        assert "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14,ICE-PHISHING-PERMITTED-ERC20-TRANSFER,hash3"  in base_alerts, "should be hash3"
        assert "0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c,SEAPORT-PHISHING-TRANSFER,hash1" in base_alerts, "should be hash1"
        
        assert 'base_alert_4' not in finding.metadata.keys(), "should not be in metadata"
        
        
    
    def test_scam_finding_manual(self):
        finding = ScamDetectorFinding.scam_finding_manual(block_chain_indexer, EOA_ADDRESS, "test", 1)  # this EOA deployed a contract
        assert finding.alert_id == "SCAM-DETECTOR-MANUAL", "should be SCAM-DETECTOR-MANUAL"
        assert finding.description == f'{EOA_ADDRESS} likely involved in an attack (SCAM-DETECTOR-MANUAL)', "should be SCAM-DETECTOR-MANUAL"
        assert finding.metadata['comment'] == "test", "should be test"
        assert len(finding.labels) == 2, "should be 2"  # one for EOA and one for contract
        assert finding.labels[0].entity == EOA_ADDRESS, "should be EOA_ADDRESS"
        assert finding.labels[1].entity == CONTRACT, "should be CONTRACT"
        assert finding.labels[0].metadata['alert_ids'] == "SCAM-DETECTOR-MANUAL", "should be SCAM-DETECTOR-MANUAL"
        assert finding.labels[0].metadata['chain_id'] == 1, "should be 1"
        assert finding.labels[0].metadata['comment'] == "test", "should be test"
        assert finding.labels[0].label == "scammer", "should be scammer"
    
    def test_alert_FP(self):
        finding = ScamDetectorFinding.alert_FP(EOA_ADDRESS)
        assert finding.alert_id == "SCAM-DETECTOR-1-FALSE-POSITIVE", "should be FP"
        assert finding.description == f'{EOA_ADDRESS} likely not involved in scam (SCAM-DETECTOR-1-FALSE-POSITIVE)', "should be FP"
        assert len(finding.labels) == 1, "should be 1"
        
    def test_alert_FP_cluster(self):
        finding = ScamDetectorFinding.alert_FP(EOA_ADDRESS+","+EOA_ADDRESS_2)
        assert finding.alert_id == "SCAM-DETECTOR-1-FALSE-POSITIVE", "should be FP"
        assert len(finding.labels) == 2, "should be 2"
    