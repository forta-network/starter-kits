from forta_agent import create_alert_event

import agent
import json
import os
from datetime import datetime, timedelta
from constants import (ALERT_MAX_QUEUE_SIZE, ALERTS_LOOKBACK_WINDOW_IN_HOURS, BASE_BOTS,
                       ALERTS_KEY, ALERTED_CLUSTERS_KEY, ENTITY_CLUSTER_ALERTS_KEY, FP_MITIGATION_ALERTS_KEY)
from web3_mock import CONTRACT, EOA_ADDRESS, Web3Mock

w3 = Web3Mock()


class TestAlertCombiner:

    def remove_persistent_state():
        if os.path.isfile(ALERTS_KEY):
            os.remove(ALERTS_KEY)
        if os.path.isfile(ALERTED_CLUSTERS_KEY):
            os.remove(ALERTED_CLUSTERS_KEY)
        if os.path.isfile(ENTITY_CLUSTER_ALERTS_KEY):
            os.remove(ENTITY_CLUSTER_ALERTS_KEY)
        if os.path.isfile(FP_MITIGATION_ALERTS_KEY):
            os.remove(FP_MITIGATION_ALERTS_KEY)

    def test_is_contract_eoa(self):
        assert not agent.is_contract(w3, EOA_ADDRESS), "EOA shouldn't be identified as a contract"

    def test_is_contract_contract(self):
        assert agent.is_contract(w3, CONTRACT), "Contract should be identified as a contract"

    def test_is_contract_contract_eoa(self):
        assert not agent.is_contract(w3, f"{CONTRACT},{EOA_ADDRESS}"), "EOA & Contract shouldnt be identified as a contract"

    def test_is_contract_contracts(self):
        assert agent.is_contract(w3, f"{CONTRACT},{CONTRACT}"), "Contracts should be identified as a contract"

    def test_is_contract_null(self):
        assert not agent.is_contract(w3, '0x0000000000a00000000000000000000000000000'), "EOA shouldn't be identified as a contract"

    def test_is_address_valid(self):
        assert agent.is_address(w3, '0x7328BBc3EaCfBe152f569f2C09f96f915F2C8D73'), "this should be a valid address"

    def test_is_address_aaa(self):
        assert not agent.is_address(w3, '0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_is_addresses_aaa(self):
        assert not agent.is_address(w3, f'0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73,{EOA_ADDRESS}'), "this shouldnt be a valid address"

    def test_is_address_aAa(self):
        assert not agent.is_address(w3, '0x7328BBaaaaAaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_in_list(self):
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "IMPOSSIBLE-2",
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })

        assert agent.in_list(alert, BASE_BOTS), "should be in list"

    def test_in_list_incorrect_alert_id(self):
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "IMPOSSIBLE-1",
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })

        assert not agent.in_list(alert, BASE_BOTS), "should be in list"

    def test_in_list_incorrect_bot_id(self):
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "IMPOSSIBLE-2",
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b51xxx"}}
                 }
             })

        assert not agent.in_list(alert, BASE_BOTS), "should be in list"

    def test_initialize(self):
        subscription_json = agent.initialize()
        json.dumps(subscription_json)
        assert True, "Bot should initialize successfully"

    def test_update_list(self):
        TestAlertCombiner.remove_persistent_state()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "IMPOSSIBLE-2",
                 "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S%fZ"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })
        alert_list = []
        agent.update_list(alert, ALERT_MAX_QUEUE_SIZE, BASE_BOTS, ALERTS_LOOKBACK_WINDOW_IN_HOURS, alert_list)

        assert len(alert_list) == 1, "should be in list"

    def test_update_list_old_alert(self):
        TestAlertCombiner.remove_persistent_state()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "IMPOSSIBLE-2",
                 "createdAt": (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S%fZ"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })
        alert_list = []
        agent.update_list(alert, ALERT_MAX_QUEUE_SIZE, BASE_BOTS, ALERTS_LOOKBACK_WINDOW_IN_HOURS, alert_list)

        assert len(alert_list) == 0, "should not be in list as the alert is too old"

    def test_update_list_queue_limit(self):
        TestAlertCombiner.remove_persistent_state()
        alert_list = []
        for i in range(0, 11):
            alert = create_alert_event(
                {"alert":
                    {"name": "x",
                     "hash": "0xabc",
                     "description": "description",
                     "alertId": "IMPOSSIBLE-2",
                     "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S%fZ"),  # 2022-11-18T03:01:21.457234676Z
                     "source":
                        {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                     }
                 })

            agent.update_list(alert, 10, BASE_BOTS, ALERTS_LOOKBACK_WINDOW_IN_HOURS, alert_list)

        assert len(alert_list) == 10, "should not be in list as the alert is too old"

    def test_persist_and_load(self):
        TestAlertCombiner.remove_persistent_state()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "IMPOSSIBLE-2",
                 "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S%fZ"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })
        alert_list = []
        agent.update_list(alert, ALERT_MAX_QUEUE_SIZE, BASE_BOTS, ALERTS_LOOKBACK_WINDOW_IN_HOURS, alert_list)

        assert len(alert_list) == 1, "should be in list"

        agent.persist(alert_list, ALERTS_KEY)
        alert_list_loaded = agent.load(ALERTS_KEY)

        assert len(alert_list_loaded) == 1, "should be in loaded list"
