import json
from datetime import datetime, timedelta, timezone
import agent
from forta_agent import create_alert_event

class TestAttackNotifier:
    def test_initialize(self):
        subscription_json = agent.initialize()
        json.dumps(subscription_json)
        assert True, "Bot should initialize successfully"

    
    def test_get_etherscan_labels(self):
        address = '0x1673888242bad06cc87a7bcaff392cb27218b3e3' # Uniswap V3: FORT-USDC 
        labels = agent.get_etherscan_labels(address, 1)
        assert labels == {'Uniswap V3: FORT-USDC', 'Uniswap'}, "should return two Uniswap labels"

    def test_notification(self):
        onyx_exploiter = "0x085bDfF2C522e8637D4154039Db8746bb8642BfF".lower()
        bot_id = "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1"
        created_date = datetime.now(timezone.utc) - timedelta(minutes=61)
        alert_json = {"alert":
                    {"name": "x",
                    "hash": "0x123",
                    "addresses": [],
                    "chainId": 1,
                    "description": f"{onyx_exploiter} description",
                    "alertId": "ATTACK-DETECTOR-2",
                    "createdAt": created_date.strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                    "source":
                        {"sourceAlert": {'botId': bot_id, 'hash': "0xabc", 'chainID': 1}},
                    "metadata": {},
                    }
                    }
        alert = create_alert_event(alert_json)
        findings = agent.handle_alert(alert)
        assert len(findings) == 0, "should return one finding"

        findings = agent.handle_block(None)
        assert len(findings) == 1, "should return one finding"
        assert findings[0].description == "0x085bdff2c522e8637d4154039db8746bb8642bff have been associated with Onyx Protocol Exploiter", "should return finding with correct name"

    def test_queue_no_alert(self):
        onyx_exploiter = "0x085bDfF2C522e8637D4154039Db8746bb8642BfF".lower()
        bot_id = "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1"
        created_date = datetime.now(timezone.utc) - timedelta(minutes=55)
        alert_json = {"alert":
                    {"name": "x",
                    "hash": "0x123",
                    "addresses": [],
                    "chainId": 1,
                    "description": f"{onyx_exploiter} description",
                    "alertId": "ATTACK-DETECTOR-2",
                    "createdAt": created_date.strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                    "source":
                        {"sourceAlert": {'botId': bot_id, 'hash': "0xabc", 'chainID': 1}},
                    "metadata": {},
                    }
                    }
        alert = create_alert_event(alert_json)
        findings = agent.handle_alert(alert)
        assert len(findings) == 0, "should return zero finding as the alert is still queued"

        findings = agent.handle_block(None)
        assert len(findings) == 0, "should return zero finding as the alert is still queued"

