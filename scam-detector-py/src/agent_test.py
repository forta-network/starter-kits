from forta_agent import create_alert_event,FindingSeverity, AlertEvent, Label, EntityType
import agent
import json
import pandas as pd
import numpy as np
import random
import requests
import os
import io
from datetime import datetime
from web3_mock import Web3Mock, EOA_ADDRESS_2, EOA_ADDRESS, CONTRACT
from constants import MODEL_ALERT_THRESHOLD_LOOSE, MODEL_ALERT_THRESHOLD_STRICT

w3 = Web3Mock()


class TestScamDetector:
    def remove_persistent_state():
        persistent_state = ['V3-alerted_clusters_loose_key', 'V3-alerted_clusters_strict_key', 'V3-alerted_fp_clusters_key', 'V3-entity_clusters_key', 'V3-fp_mitigation_clusters_key']
        for key in persistent_state:
            if os.path.exists(key):
                os.remove(key)

    def generate_alert(address: str, bot_id: str, alert_id: str, timestamp: int, metadata={}, labels=[], alert_hash = '0xabc') -> AlertEvent:
        # {
        #       "label": "Attacker",
        #       "confidence": 0.25,
        #       "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99B3820",
        #       "entityType": "ADDRESS",
        #       "remove": false
        # },

        if len(labels)>0:
            alert = {"alert":
                    {"name": "x",
                    "hash": alert_hash,
                    "addresses": [],
                    "description": f"{address} description",
                    "alertId": alert_id,
                    "createdAt": datetime.fromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                    "source":
                        {"bot": {'id': bot_id}, "block": {"chainId": 1, 'number': 5},  'transactionHash': '0x123'},
                    "metadata": metadata,
                    "labels": labels
                    }
                    }
        else:
            addresses = [address] 
            alert = {"alert":
                    {"name": "x",
                    "hash": alert_hash,
                    "addresses": addresses,
                    "description": f"{address} description",
                    "alertId": alert_id,
                    "createdAt": datetime.fromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                    "source":
                        {"bot": {'id': bot_id}, "block": {"chainId": 1, 'number': 5}, 'transactionHash': '0x123'},
                    "metadata": metadata,
                   
                    }
                    }
        return create_alert_event(alert)
    
    def test_is_contract(self):
        assert agent.is_contract(w3, EOA_ADDRESS) == False, "should be false"
        assert agent.is_contract(w3, CONTRACT) == True, "should be false"
        
    
    def test_initialize(self):
        subscription_json = agent.initialize()
        json.dumps(subscription_json)
        assert True, "Bot should initialize successfully"

    def test_in_list(self):
        agent.initialize()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "SUSPICIOUS-CONTRACT-CREATION",
                 "source":
                    {"bot": {'id': "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99"}}
                 }
             })

        assert agent.in_list(alert, agent.BASE_BOTS), "should be in list"

    def test_in_list_incorrect_alert_id(self):
        agent.initialize()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL-INCORRECT",
                 "source":
                    {"bot": {'id': "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"}}
                 }
             })

        assert not agent.in_list(alert, agent.BASE_BOTS), "should be in list"

    def test_in_list_incorrect_bot_id(self):
        agent.initialize()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL",
                 "source":
                    {"bot": {'id': "0xe8527df509859e531e58ba4154e9157eb6d9b2da202516a66ab120deabdaaaaa"}}
                 }
             })

        assert not agent.in_list(alert, agent.BASE_BOTS), "should be in list"


    # currently failing as the base bots dont emit a benign label yet
    def test_get_fp_mitigation_bot_labels(self):
        labels = agent.get_fp_mitigation_bot_labels("0xf167b212b1c73c6a8e11fcb03780e33cdb550b9e")
        assert len(labels)>0, "should be at least one label"
        assert "benign" in labels, "should be benign label"
    
    def test_get_etherscan_label_has_label(self):
        labels = agent.get_etherscan_label("0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc")
        assert "sanctioned" in ",".join(labels), "should be sanctioned label"

    def test_get_etherscan_label_no_label(self):
        labels = agent.get_etherscan_label("0xa0109274F53609f6Be97ec5f3052C659AB80f012")
        assert len(labels) == 0, "should be no label"

    def test_get_shard(self):
        package_json = json.load(open("package.json"))
        chain_id = 1
        total_chards = package_json["chainSettings"][str(chain_id)]["shards"]

        assert total_chards == 3

        for block_number in range(1, total_chards):
            shard = agent.get_shard(block_number)
            assert shard == block_number, "should be " + str(block_number)

        shard = agent.get_shard(total_chards)
        assert shard == 0, "should be 0"

    def test_put_alert(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

       
        timestamp = 1679508064
        alert = TestScamDetector.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-4", timestamp)
        agent.put_alert(alert, EOA_ADDRESS)
        agent.put_alert(alert, EOA_ADDRESS)

        alerts = agent.read_alerts(EOA_ADDRESS)
        assert len(alerts) == 1, "should be 1 alert"
        assert ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-4", "0xabc") in alerts, "should be in alerts"

    def test_put_alert_multiple_shards(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))


        timestamp_1 = 1679508064
        shard1 = agent.get_shard(timestamp_1)

        timestamp_2 = timestamp_1 + 1
        shard2 = agent.get_shard(timestamp_2)
        assert shard1 != shard2, "should be different shards"

        alert = TestScamDetector.generate_alert(EOA_ADDRESS_2, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-1", timestamp_1)
        agent.put_alert(alert, EOA_ADDRESS_2)

        alert = TestScamDetector.generate_alert(EOA_ADDRESS_2, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-2", timestamp_2)
        agent.put_alert(alert, EOA_ADDRESS_2)

        alerts = agent.read_alerts(EOA_ADDRESS_2)
        assert len(alerts) == 2, "should be 2 alert"
        assert ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-1", "0xabc") in alerts, "should be in alerts"
        assert ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-2", "0xabc") in alerts, "should be in alerts"

    def test_build_feature_vector(self):
        # alerts are tuples of (botId, alertId, alertHash)
        alerts = [('0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5', 'FLASHBOTS-TRANSACTIONS', '0x1'),
                  ('0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14', 'ICE-PHISHING-ERC20-PERMIT', '0x2'),
                  ('0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14', 'ICE-PHISHING-ERC721-APPROVAL-FOR-ALL', '0x3'),
                  ('0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14', 'ICE-PHISHING-ERC721-APPROVAL-FOR-ALL', '0x4')
                  ]

        df_expected_feature_vector = pd.DataFrame(columns=agent.MODEL_FEATURES)
        df_expected_feature_vector.loc[0] = np.zeros(len(agent.MODEL_FEATURES))
        df_expected_feature_vector.iloc[0]["0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_FLASHBOTS-TRANSACTIONS"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC20-PERMIT"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL"] = 2
        df_expected_feature_vector.iloc[0]["0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_count"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_count"] = 3

        df_expected_feature_vector = df_expected_feature_vector.sort_index(axis=1)  # sort columns alphabetically

        df_feature_vector = agent.build_feature_vector(alerts, EOA_ADDRESS)
        assert df_feature_vector.equals(df_expected_feature_vector), "should be equal"

    def test_get_score(self):
        agent.initialize()

        df_expected_feature_vector = pd.DataFrame(columns=agent.MODEL_FEATURES)
        df_expected_feature_vector.loc[0] = np.zeros(len(agent.MODEL_FEATURES))

        df_expected_feature_vector.iloc[0]["0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_NORMAL-TOKEN-TRANSFERS-TX"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS"] = 3
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-SUSPICIOUS-APPROVAL"] = 5
        df_expected_feature_vector.iloc[0]["0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_ASSET-DRAINED"] = 3
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_count"] = 10
        df_expected_feature_vector.iloc[0]["0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_count"] = 3
        df_expected_feature_vector.iloc[0]["0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_count"] = 1

        score = agent.get_model_score(df_expected_feature_vector)
        assert score > MODEL_ALERT_THRESHOLD_LOOSE, "should greater than model threshold"

    def test_get_score_empty_features(self):
        agent.initialize()

        df_expected_feature_vector = pd.DataFrame(columns=agent.MODEL_FEATURES)
        df_expected_feature_vector.loc[0] = np.zeros(len(agent.MODEL_FEATURES))
        

        score = agent.get_model_score(df_expected_feature_vector)
        assert score < MODEL_ALERT_THRESHOLD_LOOSE, "should less than model threshold"
    def test_scam_critical(self):


        TestScamDetector.remove_persistent_state()

        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        label = {"label": "Scammer",
                 "confidence": 0.25,
                 "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99B3820",
                 "entityType": EntityType.Address
                 }

        alerts = {"0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_NORMAL-TOKEN-TRANSFERS-TX": 1,
                  "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL": 1,
                  "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS": 3,
                  "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS": 1,
                  "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-SUSPICIOUS-APPROVAL": 5,
                  "0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_ASSET-DRAINED": 3}

        timestamp = datetime.now().timestamp()
        all_findings = []
        count = 1
        for alert_key in alerts.keys():
            num_alerts = alerts[alert_key]
            for i in range(num_alerts):
                bot_id = alert_key.split("_")[0]
                alert_id = alert_key.split("_")[1]
                alert_hash = str(hex(count))
                alert = TestScamDetector.generate_alert(EOA_ADDRESS, bot_id, alert_id, timestamp, {}, [label], alert_hash)
                findings = agent.detect_scam(w3, alert)
                all_findings.extend(findings)
                count += 1

        assert len(all_findings) == 1, "should have one finding"
        assert all_findings[0].alert_id == "SCAM-DETECTOR-MODEL-1", "should be SCAM-DETECTOR-MODEL-1"
        assert all_findings[0].severity == FindingSeverity.Critical, "should be Critical"



    def test_scam_low(self):
        TestScamDetector.remove_persistent_state()

        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        label = {"label": "Scammer",
                 "confidence": 0.25,
                 "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99B3820",
                 "entityType": EntityType.Address
                 }
        
        alerts = {"0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_NORMAL-TOKEN-TRANSFERS-TX": 5,
                  "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS": 1,
                  "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-SUSPICIOUS-APPROVAL": 3
                  }

        timestamp = datetime.now().timestamp()
        all_findings = []
        count = 1
        for alert_key in alerts.keys():
            num_alerts = alerts[alert_key]
            for i in range(num_alerts):
                bot_id = alert_key.split("_")[0]
                alert_id = alert_key.split("_")[1]
                alert_hash = str(hex(count))
                alert = TestScamDetector.generate_alert(EOA_ADDRESS, bot_id, alert_id, timestamp, {}, [label], alert_hash)
                findings = agent.detect_scam(w3, alert)
                all_findings.extend(findings)
                count += 1

        assert len(all_findings) == 1, "should have one finding"
        assert all_findings[0].alert_id == "SCAM-DETECTOR-MODEL-2", "should be SCAM-DETECTOR-MODEL-2"
        assert all_findings[0].severity == FindingSeverity.Low, "should be Low"
        assert "NORMAL-TOKEN-TRANSFERS-TX" in all_findings[0].labels[0].metadata['alert_ids'], "should be all alert ids"
        assert "ICE-PHISHING-SUSPICIOUS-APPROVAL" in all_findings[0].labels[0].metadata['alert_ids'], "should be all alert ids"
        assert "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS" in all_findings[0].labels[0].metadata['alert_ids'], "should be all alert ids"
        assert "https://forta.org/attacks#ice-phishing" in all_findings[0].labels[0].metadata['threat_detection_urls'], "should be in threat detection urls"
        assert "https://forta.org/attacks" in all_findings[0].labels[0].metadata['threat_detection_urls'], "should be in threat detection urls"
        

    def test_similarity(self):
        TestScamDetector.remove_persistent_state()

        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        label = {"label": "scam",
                 "confidence": 0.95,
                 "entity": "0xcaa3aa957021c0ae52bb58858487e5801c188073",
                 "entityType": EntityType.Address
                 }

        # 0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560", "NEW-SCAMMER-CONTRACT-CODE-HASH"
        metadata = {"alert_hash":"0x1994b4b05951cc626b3f3d90d82a884b46afeefb3ae05b80b0959c3d0607693a","new_scammer_contract_address":"0xfa70143f50650fb10e47abe6cbf9ace558716294","new_scammer_eoa":"0xcaa3aa957021c0ae52bb58858487e5801c188073","scammer_contract_address":"0xc87bb952c0c045cb34a89815ca3a6fb743e6b6d8","scammer_eoa":"0xcaa3aa957021c0ae52bb58858487e5801c188074","similarity_hash":"fb486fe3fb0e1ee20751524d8b0ba52bedcdc757c4c80085450dafa219969344","similarity_score":"0.9795487117767334"}
        alert_event = TestScamDetector.generate_alert(EOA_ADDRESS, "0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560", "NEW-SCAMMER-CONTRACT-CODE-HASH", datetime.now().timestamp(), metadata, [label], "0x1")

        findings = agent.detect_scam(w3, alert_event)
        assert len(findings) == 1, "should have one finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SIMILAR-1", "should be SCAM-DETECTOR-SIMILAR-1"
        assert findings[0].description == "0xcaa3aa957021c0ae52bb58858487e5801c188073 deployed a new contract with similar code to previously identified scammer 0xcaa3aa957021c0ae52bb58858487e5801c188074"
        assert findings[0].metadata['new_scammer_contract_address'] == "0xfa70143f50650fb10e47abe6cbf9ace558716294"
        assert findings[0].metadata['scammer_contract_address'] == "0xc87bb952c0c045cb34a89815ca3a6fb743e6b6d8"
        assert findings[0].metadata['similarity_score'] == "0.9795487117767334"
        
        assert "SCAM-DETECTOR-SIMILAR-1" in findings[0].labels[0].metadata['alert_id']
        assert findings[0].labels[0].entity == "0xcaa3aa957021c0ae52bb58858487e5801c188073"
        assert findings[0].labels[0].label == "scammer-eoa"
        assert "https://forta.org/attacks" in findings[0].labels[0].metadata['threat_detection_url'], "should be in threat detection urls"
        
        assert "SCAM-DETECTOR-SIMILAR-1" in findings[0].labels[1].metadata['alert_id']
        assert findings[0].labels[1].entity == "0xfa70143f50650fb10e47abe6cbf9ace558716294"
        assert findings[0].labels[1].label == "scammer-contract"
        assert "https://forta.org/attacks" in findings[0].labels[1].metadata['threat_detection_url'], "should be in threat detection urls"
        
    def test_emit_new_fp_finding(self):
        TestScamDetector.remove_persistent_state()

        agent.initialize()

        findings = agent.emit_new_fp_finding(w3)
        df_fps = pd.read_csv("fp_list.tsv", sep="\t")
        assert len(findings) > 0, "this should have triggered FP findings"
        assert len(findings) == len(df_fps[df_fps['chain_id']==1]), "this should have triggered FP findings"

        assert findings[0].alert_id == "SCAM-DETECTOR-FALSE-POSITIVE", "should be SCAM-DETECTOR-FALSE-POSITIVE"


    def test_emit_new_manual_finding(self):
        TestScamDetector.remove_persistent_state()

        agent.initialize()

        findings = agent.emit_manual_finding(w3)
        res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/Scam-Detector-ML/scam-detector-py/manual_alert_list.tsv')
        content = res.content.decode('utf-8') if res.status_code == 200 else open('manual_alert_list.tsv', 'r').read()
        df_manual_entries = pd.read_csv(io.StringIO(content), sep='\t')
        assert len(findings) > 0, "this should have triggered FP findings"
        
        for finding in findings:
            if '0x6939432e462f7dCB6a3Ca39b9723d18a58FE9A65' in finding.description.lower():
                assert findings[0].alert_id == "SCAM-DETECTOR-MANUAL-ICE-PHISHING", "should be SCAM-DETECTOR-MANUAL-ICE-PHISHING"
                assert findings[0].description == "0x6939432e462f7dCB6a3Ca39b9723d18a58FE9A65 likely involved in an attack (SCAM-DETECTOR-MANUAL-ICE-PHISHING)", "wrong description"
                assert findings[0].metadata["reported_by"] == "@CertiKAlert https://twitter.com/CertiKAlert/status/1640288904317378560?s=20"

