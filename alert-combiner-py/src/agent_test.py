from typing import Optional
from forta_agent import create_alert_event, FindingSeverity
from forta_agent.bloom_filter import BloomFilter
from web3 import Web3
from web3.middleware import geth_poa_middleware
import agent
from src.storage import dynamo_table, get_secrets
import json
import os
from forta_agent import EntityType
from datetime import datetime, timedelta
from constants import (ALERTS_LOOKBACK_WINDOW_IN_HOURS, BASE_BOTS,
                       ALERTED_CLUSTERS_MAX_QUEUE_SIZE, ALERTED_CLUSTERS_STRICT_KEY, ALERTED_CLUSTERS_LOOSE_KEY)
from web3_mock import CONTRACT, EOA_ADDRESS, EOA_ADDRESS_2, Web3Mock
from L2Cache import VERSION
from src.dynamo_utils import DynamoUtils as du, TEST_TAG
w3 = Web3Mock()

dynamo = None

class TestAlertCombiner:

    def test_label(self):
        labels = [{"label": "Attacker","confidence":0.25,"entity":"0x123","entityType":"ADDRESS"}]
        alert = {"alert": {"name":"X","labels":labels}}
        event = create_alert_event(alert)
        event.alert.labels[0].label
        event.alert.labels[0].entity


    def test_is_polygon_validator(self):
        polygon_rpc = "https://polygon-rpc.com"
        polygon_tx = "0x2568499d36d104dc5fd13484167ea5059dbc4298b85e395219a6fbdf6c1b77c3"
        polygon_validator = "0x26c80cc193b27d73d2c40943acec77f4da2c5bd8"
        agent.CHAIN_ID = 137
        
        w3 = Web3(Web3.HTTPProvider(polygon_rpc))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        assert agent.is_polygon_validator(w3, polygon_validator, polygon_tx), "should be a polygon validator"
        agent.CHAIN_ID = 1

    def remove_persistent_state(du):
        global dynamo
        try:
            # initialize dynamo DB
            if dynamo is None:
                secrets = get_secrets()
                dynamo = dynamo_table(secrets)      
        except Exception as e:
           raise e
        du.clean_db(dynamo)

        if os.path.isfile(f"{VERSION}-{ALERTED_CLUSTERS_STRICT_KEY}"):
            os.remove(f"{VERSION}-{ALERTED_CLUSTERS_STRICT_KEY}")
        if os.path.isfile(f"{VERSION}-{ALERTED_CLUSTERS_LOOSE_KEY}"):
            os.remove(f"{VERSION}-{ALERTED_CLUSTERS_LOOSE_KEY}")

    def test_in_list(self):
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "AK-ATTACK-SIMULATION-0",
                 "source":
                    {"bot": {'id': "0xe8527df509859e531e58ba4154e9157eb6d9b2da202516a66ab120deabd3f9f6"}}
                 }
             })

        assert agent.in_list(alert, BASE_BOTS), "should be in list"

    def test_in_list_incorrect_alert_id(self):
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "AK-ATTACK-SIMULATION-1",
                 "source":
                    {"bot": {'id': "0xe8527df509859e531e58ba4154e9157eb6d9b2da202516a66ab120deabd3f9f6"}}
                 }
             })

        assert not agent.in_list(alert, BASE_BOTS), "should be in list"

    def test_in_list_incorrect_bot_id(self):
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "AK-ATTACK-SIMULATION-1",
                 "source":
                    {"bot": {'id': "0xe8527df509859e531e58ba4154e9157eb6d9b2da202516a66ab120deabd3f9f6"}}
                 }
             })

        assert not agent.in_list(alert, BASE_BOTS), "should be in list"

    def test_initialize(self):
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))

        subscription_json = agent.initialize()
        json.dumps(subscription_json)
        assert True, "Bot should initialize successfully"

    def test_update_list(self):
        items = []
        agent.update_list(items, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, '0xabc')

        assert len(items) == 1, "should be in list"

    def test_update_list_queue_limit(self):
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        items = []
        for i in range(0, 11):
            agent.update_list(items, 10, str(i))

        assert len(items) == 10, "there should be 10 items in list"
        assert '0' not in items, "first item should have been removed"

    def test_persist_and_load(self):
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        chain_id = 1

        items = []
        agent.update_list(items, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, '0xabc')

        assert len(items) == 1, "should be in list"

        agent.persist(items, chain_id, ALERTED_CLUSTERS_STRICT_KEY)
        items_loaded = agent.load(chain_id, ALERTED_CLUSTERS_STRICT_KEY)

        assert len(items_loaded) == 1, "should be in loaded list"

    def test_persist_and_initialize(self):
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        chain_id = 1
        items = []
        agent.update_list(items, 10, '0xabc')

        assert len(items) == 1, "should be in list"

        agent.persist(items, chain_id, ALERTED_CLUSTERS_LOOSE_KEY)
        agent.initialize()
        items_loaded = agent.load(chain_id, ALERTED_CLUSTERS_LOOSE_KEY)

        assert len(items_loaded) == 1, "should be in loaded list"

    def generate_alert(address: str, bot_id: str, alert_id: str, metadata={}, labels=[], chain_id: Optional[int] = 1, hash: Optional[str] = "0xabc", address_filter=None):
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
                    "hash": hash,
                    "addresses": [],
                    "chainId": chain_id,
                    "description": f"{address} description",
                    "alertId": alert_id,
                    "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                    "source":
                        {"bot": {'id': bot_id}, "block": {}, 'transactionHash': '0x123'},
                    "metadata": metadata,
                    "labels": labels,
                    "addressBloomFilter": address_filter
                    }
                    }
        else:
            addresses = [address] 
            alert = {"alert":
                    {"name": "x",
                    "hash": hash,
                    "addresses": addresses,
                    "chainId": chain_id,
                    "description": f"{address} description",
                    "alertId": alert_id,
                    "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                    "source":
                        {"bot": {'id': bot_id}, "block": {}, 'transactionHash': '0x123'},
                    "metadata": metadata,
                    "addressBloomFilter": address_filter
                    }
                    }
        return create_alert_event(alert)

    def test_alert_simple_case(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        agent.CHAIN_ID = 1
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        assert abs(findings[0].metadata["anomaly_score"] - 1e-10) < 1e-20, 'incorrect anomaly score'

    def test_alert_simple_case_bloom_filter(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        
        address_filter_values_1 = [11, 4, 'test_1_base64_data']
        address_filter_1 = {
            'k': address_filter_values_1[0],
            'm': address_filter_values_1[1],
            'bitset': address_filter_values_1[2]
        }

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)}, [], 1, "0xabcd", address_filter_1)  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        address_filter_values_2 = [5, 41, 'test_2_base64_data']
        address_filter_2 = {
            'k': address_filter_values_2[0],
            'm': address_filter_values_2[1],
            'bitset': address_filter_values_2[2]
        }

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)}, [], 1, "0xabcde", address_filter_2)  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        assert len(findings) == 1, "alert should have been raised"
        assert findings[0].metadata['involved_address_bloom_filter_0'] == None, 'incorrect involved_address_bloom_filter_0'
        assert findings[0].metadata['involved_address_bloom_filter_1'] == address_filter_values_1, 'incorrect involved_address_bloom_filter_1'
        assert findings[0].metadata['involved_address_bloom_filter_2'] == address_filter_values_2, 'incorrect involved_address_bloom_filter_2'
        
    def test_alert_simple_case_L2_no_findings(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # all alert have been raised on L1
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        agent.CHAIN_ID = 10
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)


        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 0, "alert should have been raised"
       
    def test_alert_simple_case_L2_findings(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # final alert raised on L2
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        agent.CHAIN_ID = 10
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"
        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)}, [], 10)  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        assert abs(findings[0].metadata["anomaly_score"] - 1e-10) < 1e-20, 'incorrect anomaly score'

    def test_alert_highly_precise_bots(self):
        # two alerts in two stages for a given EOA for a given highly precise bot
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        agent.CHAIN_ID = 1
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # smart contract ML bot
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        assert len(findings) == 1, "alert should have been raised"


    def test_get_attacker_from_labels(self):
        labels = [
                    {"label": "Attacker",
                    "confidence": 0.25,
                    "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99AAAAA",
                    "entityType": "ADDRESS"
                    },
                    {"label": "attack-contract",
                    "confidence": 0.25,
                    "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99BBBBB",
                    "entityType": "ADDRESS"
                    },
                    {"label": "victim",
                    "confidence": 0.25,
                    "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99CCCCC",
                    "entityType": EntityType.Address
                    },
                ]
        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)}, labels)  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        
        attacker_addresses = agent.get_pot_attacker_addresses(alert_event)
        assert len(attacker_addresses) == 2, "should be two attacker addresses"
        assert "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99AAAAA" in attacker_addresses, "should be attacker address"
        assert "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99BBBBB" in attacker_addresses, "should be attacker address"
        assert "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99CCCCC" not in attacker_addresses, "should not be attacker address"
        

    def test_alert_simple_case_with_labels(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)
        label = {"label": "Attacker",
                 "confidence": 0.25,
                 "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99B3820",
                 "entityType": EntityType.Address
                 }

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)}, [label])  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)}, [label])  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)}, [label])  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        assert abs(findings[0].metadata["anomaly_score"] - 1e-10) < 1e-20, 'incorrect anomaly score'
    
    def test_alert_simple_case_no_labels(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        assert abs(findings[0].metadata["anomaly_score"] - 1e-10) < 1e-20, 'incorrect anomaly score'


    def test_alert_simple_case_missing_anomaly_score(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION")  
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 1.0 * 50/10000000 -> 5E-9

        assert len(findings) == 1, "alert should have been raised given three alerts and score exceeds threshold"
        assert abs(findings[0].metadata["anomaly_score"] - 5e-9) < 1e-20, 'incorrect anomaly score'

    def test_alert_simple_case_with_victim(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        metadata = {"address1": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "holders1": "", "protocolTwitter1": "wrappedEth", "protocolUrl1": "", "tag1": "Wrapped Ether"}
        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x441d3228a68bbbcf04e6813f52306efcaf1e66f275d682e62499f44905215250", "VICTIM-IDENTIFIER-PREPARATION-STAGE", metadata)  # contains victim info
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100.0/100000 * 200.0/10000 * 50.0/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        assert abs(findings[0].metadata["anomaly_score"] - 1e-10) < 1e-20, 'incorrect anomaly score'
        assert "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".lower() in findings[0].description, "victim not included in description"
        assert "Wrapped Ether" in findings[0].description, "victim name not included in description"

    def test_alert_repeat_alerts(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        findings = []

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        assert len(findings) == 0, "alert should not have been raised again"

    def test_alert_simple_case_contract(self):
        # three alerts in diff stages for a given contract
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(CONTRACT, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(CONTRACT, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(CONTRACT, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        assert len(findings) == 0, "alert should have been raised as this is a contract"

    def test_alert_simple_case_older_alerts(self):
        # three alerts in diff stages for a given older alerts
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        alert_event.alert.created_at = (datetime.now() - timedelta(hours=ALERTS_LOOKBACK_WINDOW_IN_HOURS + 1)).strftime("%Y-%m-%dT%H:%M:%S.%f123Z")
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        assert len(findings) == 0, "alert should not have been raised funding alert is too old"

    def test_alert_proper_handling_of_min(self):
        # three alerts in diff stages for a given older alerts
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x0e82982faa7878af3fad8ddf5042762a3b78d8949da2e301f1adfedc973f25ea", "EXPLOITER-ADDR-TX", {"anomaly_score": (1000.0 / 10000000)})  # preparation -> alert count = 1000, blocklist account tx; ad-scorer contract-creation -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 1, "only 1 alert should have been raised"
        assert findings[0].severity == FindingSeverity.Low, "low severity alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        

        # 100/100000 * 1000/10000000 * 50/10000000 -> 5E-13
        assert len(findings) == 1, "alert should have been raised"
        assert findings[0].severity == FindingSeverity.Critical, "critical severity alert should have been raised"
        assert abs(findings[0].metadata["anomaly_score"] - 5e-13) < 1e-20, 'incorrect anomaly score'

    def test_alert_too_few_alerts(self):
        # two alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 50/10000000 -> 5E-9
        assert len(findings) == 0, "no alert should have been raised"

    def test_alert_FP_mitigation(self):
        # FP mitigation
        # three alerts in diff stages for a given EOA
        # anomaly score < 10 E-8

        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "POSITIVE-REPUTATION-1")  # positive reputation alert
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "ATTACK-DETECTOR-5 alert should have been raised as this is FP mitigated"
        assert findings[0].alert_id == "ATTACK-DETECTOR-5", "ATTACK-DETECTOR-5 alert should have been raised as this is FP mitigated"
        assert findings[0].severity == FindingSeverity.Info, "info severity alert should have been raised"

    def test_alert_cluster_alert(self):
        # three alerts in diff stages across two EOAs that are clustered
        # no FP
        # anomaly score < 10 E-8

        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9", "ENTITY-CLUSTER", {"entityAddresses": f"{EOA_ADDRESS},{EOA_ADDRESS_2}"})  # entity clustering alert
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})   # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings =  agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})   # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS_2, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})   # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        assert abs(findings[0].metadata["anomaly_score"] - 1e-10) < 1e-20, 'incorrect anomaly score'

    def test_alert_cluster_alert_after(self):
        # three alerts in diff stages across two EOAs that are clustered, but the cluster comes in after some key alerts are raised
        # no FP
        # anomaly score < 10 E-8

        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS_2, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})   # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9", "ENTITY-CLUSTER", {"entityAddresses": f"{EOA_ADDRESS},{EOA_ADDRESS_2}"})  # entity clustering alert
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})   # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        assert abs(findings[0].metadata["anomaly_score"] - 1e-10) < 1e-20, 'incorrect anomaly score'


    def test_alert_with_end_user_attack(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state(du(TEST_TAG, agent.CHAIN_ID))
        agent.initialize()
        dynamo_utils = du(TEST_TAG, agent.CHAIN_ID)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", {"anomaly_score": (100.0 / 100000)})  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", {"anomaly_score": (200.0 / 10000)})  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        metadata = {"attacker_deployer_address": EOA_ADDRESS, "rugpull_techniques": "HIDDENTRANSFERREVERTS, HONEYPOT", "token_contract_address": "0xC159B59Bb001d26e69A7a6F278939559A0a5028a"}
        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15", "HARD-RUG-PULL-1", metadata)  # this is an end user alert; should be ignored in context of AD calculation
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)
        assert len(findings) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", {"anomaly_score": (50.0 / 10000000)})  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        findings = agent.detect_attack(w3, dynamo_utils, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-10

        assert len(findings) == 1, "alert should have been raised"
        assert findings[0].alert_id == "ATTACK-DETECTOR-6", "ATTACK-DETECTOR-6 alert should have been raised as this associated with end user attack"
