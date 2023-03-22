# Copyright 2022 The Forta Foundation

from forta_agent import create_alert_event, FindingSeverity, FindingType

import agent
import json
import os
from datetime import datetime
from constants import CACHE_VERSION, CONTRACT_CACHE_KEY, ADDRESS_TO_SOURCE_BOT_MAPPING_KEY

EOA_ADDRESS = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4'


class TestPositiveReputation:

    def remove_persistent_state():
        if os.path.isfile(f"{CACHE_VERSION}-{CONTRACT_CACHE_KEY}"):
            os.remove(f"{CACHE_VERSION}-{CONTRACT_CACHE_KEY}")
        if os.path.isfile(f"{CACHE_VERSION}-{ADDRESS_TO_SOURCE_BOT_MAPPING_KEY}"):
            os.remove(f"{CACHE_VERSION}-{ADDRESS_TO_SOURCE_BOT_MAPPING_KEY}")

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

    def test_simple_alert_and_label(self):

        TestPositiveReputation.remove_persistent_state()
        agent.initialize()

        alert_event = TestPositiveReputation.generate_alert_with_description(EOA_ADDRESS, "0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "POSITIVE-REPUTATION-1")
        findings = agent.process_alert(alert_event)
        assert len(findings) == 1, "alert should have been raised"
        assert findings[0].severity == FindingSeverity.Info, "alert should have severity of Info"
        assert findings[0].type == FindingType.Info, "alert should have severity of Info"
        assert findings[0].metadata["base_bots_1"] == "0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "alert's metadata should have base bot 0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f specified"

        assert len(findings[0].labels) == 1, "label should have been added"
        assert findings[0].labels[0].entity == EOA_ADDRESS.lower(), "label should have been added"
        assert findings[0].labels[0].confidence == 0.3, "label should have confidence of 0.3"

    def test_multiple_bot_alert_and_label(self):

        TestPositiveReputation.remove_persistent_state()
        agent.initialize()

        alert_event = TestPositiveReputation.generate_alert_with_description(EOA_ADDRESS, "0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "POSITIVE-REPUTATION-1")
        agent.process_alert(alert_event)

        alert_event = TestPositiveReputation.generate_alert_with_description(EOA_ADDRESS, "0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b", "MEV-ACCOUNT")
        findings = agent.process_alert(alert_event)

        assert len(findings) == 1, "alert should have been raised"
        assert findings[0].metadata["base_bots_1"] == "0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "alert's metadata should have base bot 0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f specified"
        assert findings[0].metadata["base_bots_2"] == "0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b", "alert's metadata should have base bot 0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b specified"

        assert len(findings[0].labels) == 1, "label should have been added"
        assert findings[0].labels[0].entity == EOA_ADDRESS.lower(), "label should have been added"
        assert findings[0].labels[0].confidence == 0.5, "label should have confidence of 0.5"
