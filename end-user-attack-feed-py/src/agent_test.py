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

    def test_parse_indicators(self):
        attacker_address = agent.parse_indictors("0x4258ebe8ca35de27d7f60a2512015190b8ad70e7 likely involved in an attack (ATTACK-DETECTOR-ICE-PHISHING)")
        assert attacker_address == "0x4258ebe8ca35de27d7f60a2512015190b8ad70e7", "attacker address should be parsed"

    def test_simple_alert_and_label(self):
        TestPositiveReputation.remove_persistent_state()
        agent.initialize()

        alert_event = TestPositiveReputation.generate_alert_with_description(EOA_ADDRESS, "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23", "ATTACK-DETECTOR-ICE-PHISHING")
        findings = agent.process_alert(alert_event)
        assert len(findings) == 1, "alert should have been raised"
        assert findings[0].severity == FindingSeverity.Critical, "alert should have severity of Critical"
        assert findings[0].type == FindingType.Exploit, "alert should have severity of Exploit"
        assert findings[0].alert_id == "NEGATIVE-REPUTATION-END-USER-ATTACK-1", "alertid should be NEGATIVE-REPUTATION-END-USER-ATTACK-1"
        assert findings[0].metadata["bot_id"] == "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23", "alert's metadata should have bot_id 0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23 specified"
        assert findings[0].metadata["alert_id"] == "ATTACK-DETECTOR-ICE-PHISHING", "alert's metadata should have alert_id ATTACK-DETECTOR-ICE-PHISHING specified"
        assert findings[0].metadata["alert_hash"] == "0xabc", "alert's metadata should have alert hash 0xabc specified"

        assert len(findings[0].labels) == 1, "label should have been added"
        assert findings[0].labels[0].entity == EOA_ADDRESS.lower(), "label should have been added"
        assert findings[0].labels[0].label == "attacker", "attacker label should have been set"
        assert findings[0].labels[0].confidence == 0.6, "label should have confidence of 0.6"
