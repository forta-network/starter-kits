# Copyright 2022 The Forta Foundation

from forta_agent import create_alert_event, FindingSeverity, FindingType

import agent
import json
from datetime import datetime

EOA_ADDRESS = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4'


class TestPositiveReputation:

    def remove_persistent_state():
        # if os.path.isfile(f"{CACHE_VERSION}-{CONTRACT_CACHE_KEY}"):
        #     os.remove(f"{CACHE_VERSION}-{CONTRACT_CACHE_KEY}")
        return

    def generate_alert_with_description(address: str, bot_id: str, alert_id: str, metadata={}):
        alert = {"alert":
                 {"name": "x",
                  "hash": "0xabc",
                  "addresses": [address],
                  "description": f"{address} description",
                  "alertId": alert_id,
                  "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                  "source":
                     {"bot": {'id': bot_id}, "block": {"chainId": 1}, 'transactionHash': '0x123'},
                  "metadata": metadata
                  }
                 }
        return create_alert_event(alert)

    def test_initialize(self):
        TestPositiveReputation.remove_persistent_state()

        subscription_json = agent.initialize()
        json.dumps(subscription_json)
        assert True, "Bot should initialize successfully"

    def test_parse_indicators_no_victim(self):
        attacker_address, victim_address, victim_name = agent.parse_indictors_forta_foundation("0x5711caa8fdcd832ce1be554f2229345181a646ac likely involved in an attack (ATTACK-DETECTOR-2).")
        assert attacker_address == "0x5711caa8fdcd832ce1be554f2229345181a646ac", "attacker address should be parsed"
        assert victim_address == "", "victim address should be empty"
        assert victim_name == "", "victim name should be empty"

    def test_parse_indicators_with_victim(self):
        attacker_address, victim_address, victim_name = agent.parse_indictors_forta_foundation("0xe3174149f80d1ea429970ec5043e361bc003ddbd likely involved in an attack (ATTACK-DETECTOR-1 on 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 (wrapped ether))")
        assert attacker_address == "0xe3174149f80d1ea429970ec5043e361bc003ddbd", "attacker address should be parsed"
        assert victim_address == "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "victim address should be parsed"
        assert victim_name == "wrapped ether", "victim name should be parsed"

    def test_parse_indicators_blocksec(self):
        attacker_address, victim_address, victim_name = agent.parse_indictors_blocksec("The suspicious address 0x5cd7df4cd1427407cc8dbd7dd9681b5dc24df4fd made a profit about 9.793598422e+29 BNB. https://phalcon.blocksec.com/tx/bsc/0x3e1508a038bd7d584285eeb1cb5044ca00545718ae6dba4817149c186e949f43")
        assert attacker_address == "0x5cd7df4cd1427407cc8dbd7dd9681b5dc24df4fd", "attacker address should be parsed"
        assert victim_address == "", "victim address should be empty"
        assert victim_name == "", "victim name should be empty"

    def test_simple_alert_and_label(self):
        TestPositiveReputation.remove_persistent_state()
        agent.initialize()

        alert_event = TestPositiveReputation.generate_alert_with_description(EOA_ADDRESS, "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1", "ATTACK-DETECTOR-2")
        findings = agent.process_alert(alert_event)
        assert len(findings) == 1, "alert should have been raised"
        assert findings[0].severity == FindingSeverity.Critical, "alert should have severity of Critical"
        assert findings[0].type == FindingType.Exploit, "alert should have severity of Exploit"
        assert findings[0].alert_id == "NEGATIVE-REPUTATION-PROTOCOL-ATTACK-1", "alertid should be NEGATIVE-REPUTATION-PROTOCOL-ATTACK-1"
        assert findings[0].metadata["bot_id"] == "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1", "alert's metadata should have bot_id 0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1 specified"
        assert findings[0].metadata["alert_id"] == "ATTACK-DETECTOR-2", "alert's metadata should have alert_id ATTACK-DETECTOR-2 specified"
        assert findings[0].metadata["alert_hash"] == "0xabc", "alert's metadata should have alert hash 0xabc specified"

        assert len(findings[0].labels) == 1, "label should have been added"
        assert findings[0].labels[0].entity == EOA_ADDRESS.lower(), "label should have been added"
        assert findings[0].labels[0].label == "attacker", "attacker label should have been set"
        assert findings[0].labels[0].confidence == 0.6, "label should have confidence of 0.6"

    