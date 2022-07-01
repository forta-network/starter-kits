import time

import pandas as pd
from forta_agent import create_block_event

import agent
from forta_explorer_mock import FortaExplorerMock
from web3_mock import CONTRACT, EOA_ADDRESS, Web3Mock

w3 = Web3Mock()


class TestAlertCombiner:
    def test_is_contract_eoa(self):
        assert not agent.is_contract(w3, EOA_ADDRESS), "EOA shouldn't be identified as a contract"

    def test_is_contract_null(self):
        assert not agent.is_contract(w3, '0x0000000000a00000000000000000000000000000'), "EOA shouldn't be identified as a contract"

    def test_is_address_valid(self):
        assert agent.is_address(w3, '0x7328BBc3EaCfBe152f569f2C09f96f915F2C8D73'), "this should be a valid address"

    def test_is_address_aaa(self):
        assert not agent.is_address(w3, '0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_is_address_aAa(self):
        assert not agent.is_address(w3, '0x7328BBaaaaAaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_is_contract_contract(self):
        assert agent.is_contract(w3, CONTRACT), "EOA should be identified as a contract"

    def test_detect_alert_pos_finding(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Suspicious Contract Creation by Tornado Cash funded account", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99"}},
             "HIGH", {}, "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Tornado Cash Funding", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a"}},
             "HIGH", {}, "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"],

            ["2022-04-30T23:55:17.284158264Z", "Reentrancy", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
             "HIGH", {}, "NETHFORTA-25", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e12"],

            ["2022-04-30T23:55:17.284158264Z", "Money Laundering", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2"}},
             "HIGH", {}, "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH", "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 potentially engaged in money laundering", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e13"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"

    def test_detect_alert_pos_no_repeat_finding(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Suspicious Contract Creation by Tornado Cash funded account", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99"}},
             "HIGH", {}, "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Tornado Cash Funding", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a"}},
             "HIGH", {}, "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"],

            ["2022-04-30T23:55:17.284158264Z", "Reentrancy", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
             "HIGH", {}, "NETHFORTA-25", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e12"],

            ["2022-04-30T23:55:17.284158264Z", "Money Laundering", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2"}},
             "HIGH", {}, "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH", "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 potentially engaged in money laundering", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e13"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)
        time.sleep(1)
        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"
        agent.FINDINGS_CACHE = []

        agent.detect_attack(w3, forta_explorer, block_event)
        time.sleep(1)
        assert len(agent.FINDINGS_CACHE) == 0, "this should have have triggered another finding"

    def test_detect_alert_pos_nofinding(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Suspicious Contract Creation by Tornado Cash funded account", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99"}},
             "HIGH", {}, "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Tornado Cash Funding", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a"}},
             "HIGH", {}, "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"],

            ["2022-04-30T23:55:17.284158264Z", "Money Laundering", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "agent": {"id": "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2"}},
             "HIGH", {}, "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH", "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 potentially engaged in money laundering", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e13"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 0, "this should not have triggered a finding"
