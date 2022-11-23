from forta_agent import create_alert_event

import agent
import json
import os
from datetime import datetime, timedelta
from constants import (ALERTS_DATA_MAX_QUEUE_SIZE, ALERTS_LOOKBACK_WINDOW_IN_HOURS, BASE_BOTS,
                       ALERTS_DATA_KEY, ALERTED_CLUSTERS_KEY, ENTITY_CLUSTERS_KEY, FP_MITIGATION_ALERTS_KEY)
from web3_mock import CONTRACT, EOA_ADDRESS, Web3Mock
from luabase_mock import LuabaseMock

w3 = Web3Mock()
luabase = LuabaseMock()


class TestAlertCombiner:

    def remove_persistent_state():
        if os.path.isfile(ALERTS_DATA_KEY):
            os.remove(ALERTS_DATA_KEY)
        if os.path.isfile(ALERTED_CLUSTERS_KEY):
            os.remove(ALERTED_CLUSTERS_KEY)
        if os.path.isfile(ENTITY_CLUSTERS_KEY):
            os.remove(ENTITY_CLUSTERS_KEY)
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
        TestAlertCombiner.remove_persistent_state()

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
                 "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })
        alert_list = []
        agent.update_list(alert, ALERTS_DATA_MAX_QUEUE_SIZE, BASE_BOTS, ALERTS_LOOKBACK_WINDOW_IN_HOURS, alert_list)

        assert len(alert_list) == 1, "should be in list"

    def test_update_list_old_alert(self):
        TestAlertCombiner.remove_persistent_state()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "IMPOSSIBLE-2",
                 "createdAt": (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })
        alert_list = []
        agent.update_list(alert, ALERTS_DATA_MAX_QUEUE_SIZE, BASE_BOTS, ALERTS_LOOKBACK_WINDOW_IN_HOURS, alert_list)

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
                     "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
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
                 "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })
        alert_list = []
        agent.update_list(alert, ALERTS_DATA_MAX_QUEUE_SIZE, BASE_BOTS, ALERTS_LOOKBACK_WINDOW_IN_HOURS, alert_list)

        assert len(alert_list) == 1, "should be in list"

        agent.persist(alert_list, ALERTS_DATA_KEY)
        alert_list_loaded = agent.load(ALERTS_DATA_KEY)

        assert len(alert_list_loaded) == 1, "should be in loaded list"

    def test_persist_and_initialize(self):
        TestAlertCombiner.remove_persistent_state()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "IMPOSSIBLE-2",
                 "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7"}}
                 }
             })
        alert_list = []
        agent.update_list(alert, ALERTS_DATA_MAX_QUEUE_SIZE, BASE_BOTS, ALERTS_LOOKBACK_WINDOW_IN_HOURS, alert_list)

        assert len(alert_list) == 1, "should be in list"

        agent.persist(alert_list, ALERTS_DATA_KEY)
        agent.initialize()

        assert len(alert_list_loaded) == 1, "should be in loaded list"

    def generate_alert(address: str, bot_id: str, alert_id: str):
        return create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "addresses": [address],
                 "description": f"{address} description",
                 "alertId": alert_id,
                 "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': bot_id}, "block": {"chainId": 1}}
                 }
             })

    def test_alert_simple_case(self):
        # three alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state()
        agent.initialize()

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91", "SUSPICIOUS-CONTRACT-CREATION")  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 5000; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 200/10000 * 5000/10000000 -> 10E-8

        assert len(agent.FINDINGS_CACHE) == 1, "alert should have been raised"


    def test_alert_simple_case_contract(self):
        # three alerts in diff stages for a given contract
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state()
        agent.initialize()

        alert_event = TestAlertCombiner.generate_alert(CONTRACT, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(CONTRACT, "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91", "SUSPICIOUS-CONTRACT-CREATION")  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(CONTRACT, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 5000; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        #100/100000 * 200/10000 * 5000/10000000 -> 10E-8

        assert len(agent.FINDINGS_CACHE) == 0, "alert should have been raised as this is a contract"


    def test_alert_simple_case_older_alerts(self):
        # three alerts in diff stages for a given older alerts
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state()
        agent.initialize()

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        alert_event.alert.created_at = (datetime.now() - timedelta(hours=ALERTS_LOOKBACK_WINDOW_IN_HOURS + 1)).strftime("%Y-%m-%dT%H:%M:%S.%f123Z")
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91", "SUSPICIOUS-CONTRACT-CREATION")  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 5000; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 200/10000 * 5000/10000000 -> 10E-8
        assert len(agent.FINDINGS_CACHE) == 0, "alert should have been raised funding alert is too old"


    # def test_alert_proper_handling_of_min(self):
    #     # three alerts in diff stages for a given EOA
    #     # within one stage two different alerts that generate a diff anomaly score
    #     # no FP
    #     # anomaly score < 10 E-8

    #     alert = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH") # funding, TC

    #     # asset alert raised

    # def test_alert_too_few_alerts(self):
    #     # two alerts in diff stages for a given EOA
    #     # no FP
    #     # anomaly score < 10 E-8

    #     # asset alert raised

    # def test_alert_FP_mitigation(self):
    #     # three alerts in diff stages for a given EOA
    #     # FP mitigation
    #     # anomaly score < 10 E-8

    #     # asset no alert raised

    # def test_alert_cluster_alert(self):
    #     # three alerts in diff stages across two EOAs that are clustered
    #     # no FP
    #     # anomaly score < 10 E-8

    #     # asset alert raised

    # def test_alert_cluster_fp_mitigation(self):
    #     # three alerts in diff stages across two EOAs that are clustered
    #     # FP mitigation
    #     # anomaly score < 10 E-8

    #     # asset no alert raised

