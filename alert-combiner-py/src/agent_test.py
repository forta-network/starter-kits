from forta_agent import create_alert_event

import agent
import json
import os
from datetime import datetime, timedelta
from constants import (ALERTS_LOOKBACK_WINDOW_IN_HOURS, BASE_BOTS, ALERTED_CLUSTERS_MAX_QUEUE_SIZE,
                       ALERTS_DATA_KEY, ALERTED_CLUSTERS_KEY, ENTITY_CLUSTERS_KEY, FP_MITIGATION_CLUSTERS_KEY)
from web3_mock import CONTRACT, EOA_ADDRESS, EOA_ADDRESS_2, Web3Mock
from luabase_mock import LuabaseMock
from L2Cache import VERSION

w3 = Web3Mock()
luabase = LuabaseMock()


class TestAlertCombiner:

    def remove_persistent_state():
        if os.path.isfile(f"{VERSION}-{ALERTS_DATA_KEY}"):
            os.remove(f"{VERSION}-{ALERTS_DATA_KEY}")
        if os.path.isfile(f"{VERSION}-{ALERTED_CLUSTERS_KEY}"):
            os.remove(f"{VERSION}-{ALERTED_CLUSTERS_KEY}")
        if os.path.isfile(f"{VERSION}-{ENTITY_CLUSTERS_KEY}"):
            os.remove(f"{VERSION}-{ENTITY_CLUSTERS_KEY}")
        if os.path.isfile(f"{VERSION}-{FP_MITIGATION_CLUSTERS_KEY}"):
            os.remove(f"{VERSION}-{FP_MITIGATION_CLUSTERS_KEY}")

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
        items = []
        agent.update_list(items, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, '0xabc')

        assert len(items) == 1, "should be in list"

    def test_update_list_queue_limit(self):
        TestAlertCombiner.remove_persistent_state()
        items = []
        for i in range(0, 11):
            agent.update_list(items, 10, str(i))

        assert len(items) == 10, "there should be 10 items in list"
        assert '0' not in items, "first item should have been removed"

    def test_persist_and_load(self):
        TestAlertCombiner.remove_persistent_state()
        chain_id = 1

        items = []
        agent.update_list(items, ALERTED_CLUSTERS_MAX_QUEUE_SIZE, '0xabc')

        assert len(items) == 1, "should be in list"

        agent.persist(items, chain_id, ALERTS_DATA_KEY)
        items_loaded = agent.load(chain_id, ALERTS_DATA_KEY)

        assert len(items_loaded) == 1, "should be in loaded list"

    def test_persist_and_initialize(self):
        TestAlertCombiner.remove_persistent_state()
        chain_id = 1
        items = []
        agent.update_list(items, 10, '0xabc')

        assert len(items) == 1, "should be in list"

        agent.persist(items, chain_id, FP_MITIGATION_CLUSTERS_KEY)
        agent.initialize()
        items_loaded = agent.load(chain_id, FP_MITIGATION_CLUSTERS_KEY)

        assert len(items_loaded) == 1, "should be in loaded list"

    def generate_alert(address: str, bot_id: str, alert_id: str, metadata={}):
        return create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "addresses": [address],
                 "description": f"{address} description",
                 "alertId": alert_id,
                 "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                 "source":
                    {"bot": {'id': bot_id}, "block": {"chainId": 1}},
                 "metadata": metadata
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

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 10E-9

        assert len(agent.FINDINGS_CACHE) == 1, "alert should have been raised"
        assert abs(agent.FINDINGS_CACHE[0].metadata["anomaly_score"] - 1e-9) < 1e-20, 'incorrect anomaly score'

    def test_alert_repeat_alerts(self):
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

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 10E-9

        assert len(agent.FINDINGS_CACHE) == 1, "alert should have been raised"
        agent.FINDINGS_CACHE = []

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91", "SUSPICIOUS-CONTRACT-CREATION")  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        assert len(agent.FINDINGS_CACHE) == 0, "alert should not have been raised again"

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

        alert_event = TestAlertCombiner.generate_alert(CONTRACT, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

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

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        assert len(agent.FINDINGS_CACHE) == 0, "alert should have been raised funding alert is too old"

    def test_alert_proper_handling_of_min(self):
        # three alerts in diff stages for a given older alerts
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state()
        agent.initialize()

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xaedda4252616d971d570464a3ae4a9f0a9d72a57d8581945fff648d03cd30a7d", "FORTA-BLOCKLIST-ADDR-TX")  # preparation -> alert count = 1000, blocklist account tx; ad-scorer contract-creation -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91", "SUSPICIOUS-CONTRACT-CREATION")  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 1000/10000000 * 50/10000000 -> 10E-8
        assert len(agent.FINDINGS_CACHE) == 1, "alert should have been raised"
        assert abs(agent.FINDINGS_CACHE[0].metadata["anomaly_score"] - 5e-13) < 1e-20, 'incorrect anomaly score'

    def test_alert_too_few_alerts(self):
        # two alerts in diff stages for a given EOA
        # no FP
        # anomaly score < 10 E-8
        TestAlertCombiner.remove_persistent_state()
        agent.initialize()

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 50/10000000 -> 5E-9
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

    def test_alert_FP_mitigation(self):
        # FP mitigation
        # three alerts in diff stages for a given EOA
        # anomaly score < 10 E-8

        TestAlertCombiner.remove_persistent_state()
        agent.initialize()

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "POSITIVE-REPUTATION-1")  # positive reputation alert
        agent.detect_attack(w3, luabase, alert_event)

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91", "SUSPICIOUS-CONTRACT-CREATION")  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 1E-9

        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised as this is FP mitigated"

    def test_alert_cluster_alert(self):
        # three alerts in diff stages across two EOAs that are clustered
        # no FP
        # anomaly score < 10 E-8

        TestAlertCombiner.remove_persistent_state()
        agent.initialize()

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9", "ENTITY-CLUSTER", {"entityAddresses": f"{EOA_ADDRESS},{EOA_ADDRESS_2}"})  # entity clustering alert
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91", "SUSPICIOUS-CONTRACT-CREATION")  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS_2, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 10E-9

        assert len(agent.FINDINGS_CACHE) == 1, "alert should have been raised"
        assert abs(agent.FINDINGS_CACHE[0].metadata["anomaly_score"] - 1e-9) < 1e-20, 'incorrect anomaly score'

    def test_alert_cluster_alert_after(self):
        # three alerts in diff stages across two EOAs that are clustered, but the cluster comes in after some key alerts are raised
        # no FP
        # anomaly score < 10 E-8

        TestAlertCombiner.remove_persistent_state()
        agent.initialize()

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS_2, "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH")  # funding, TC -> alert count 100; ad-scorer transfer-in -> denominator 100000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91", "SUSPICIOUS-CONTRACT-CREATION")  # preparation -> alert count = 200, suspicious ML; ad-scorer contract-creation -> denominator 10000
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9", "ENTITY-CLUSTER", {"entityAddresses": f"{EOA_ADDRESS},{EOA_ADDRESS_2}"})  # entity clustering alert
        agent.detect_attack(w3, luabase, alert_event)
        assert len(agent.FINDINGS_CACHE) == 0, "no alert should have been raised"

        alert_event = TestAlertCombiner.generate_alert(EOA_ADDRESS, "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION")  # exploitation, flashbot -> alert count = 50; ad-scorer tx-count -> denominator 10000000
        agent.detect_attack(w3, luabase, alert_event)

        # 100/100000 * 200/10000 * 50/10000000 -> 10E-9

        assert len(agent.FINDINGS_CACHE) == 1, "alert should have been raised"
        assert abs(agent.FINDINGS_CACHE[0].metadata["anomaly_score"] - 1e-9) < 1e-20, 'incorrect anomaly score'
