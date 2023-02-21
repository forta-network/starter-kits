import time
import os
import pandas as pd
from forta_agent import create_block_event

import agent
from forta_explorer_mock import FortaExplorerMock
from web3_mock import CONTRACT, EOA_ADDRESS, Web3Mock, EOA_ADDRESS_LARGE_TX

w3 = Web3Mock()


class TestAlertCombiner:
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

    def test_etherscan_label(self):
        label = agent.get_etherscan_label("0xffc0022959f58aa166ce58e6a38f711c95062b99")
        assert label == 'uniswap', "this should be a uniswap address"

    def test_fp_mitigation(self):
        # delete cache file
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")
        if os.path.exists("alerted_fp_addresses_key"):
            os.remove("alerted_fp_addresses_key")

        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Tornado Cash Funding", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"}},
             "HIGH", {}, "FUNDING-TORNADO-CASH", "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 interacted with contract 0xcc5f573a93fcab719640f660173b8217664605d3", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        assert len(agent.FINDINGS_CACHE) == 2, "this should have triggered two FP finding"
        finding = agent.FINDINGS_CACHE[0]
        assert finding.alert_id == "ATTACK-DETECTOR-ICE-PHISHING-FALSE-POSITIVE", "should be FP mitigation finding"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_alert_pos_finding_combiner_3_description(self):
        # delete cache file
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")

        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Account got approval for all tokens", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"}},
             "HIGH", {}, "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days.", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Tornado Cash Funding", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"}},
             "HIGH", {}, "FUNDING-TORNADO-CASH", "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 interacted with contract 0xcc5f573a93fcab719640f660173b8217664605d3", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"
        finding = agent.FINDINGS_CACHE[0]
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"


    def test_detect_alert_pos_finding_combiner_3_metadata(self):
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")

        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Account got approval for all tokens", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"}},
             "HIGH", {}, "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days.", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x22abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Malicious Address", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895"}},
             "HIGH", {"amount":"0","from":"0x4f07bb5b0c204da3d1c7a35dab23114ac2145980","malicious_details":"[{'index': '609', 'id': '1ae52e', 'name': 'moonbirdsraffle.xyz', 'type': 'scam', 'url': 'https://moonbirdsraffle.xyz', 'hostname': 'moonbirdsraffle.xyz', 'featured': '0', 'path': '/*', 'category': 'Phishing', 'subcategory': 'Moonbirds', 'description': 'Fake Moonbirds NFT site phishing for funds', 'reporter': 'CryptoScamDB', 'severity': '1', 'updated': '1.65635E+12', 'address': '0x21e13f16838e2fe78056f5fd50251ffd6e7098b4'}]","to":"0x335eeef8e93a7a757d9e7912044d9cd264e2b2d8"}, "AE-MALICIOUS-ADDR", "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 obtained", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"

    def test_detect_alert_pos_finding_combiner_3_tx_to(self):
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Account got approval for all tokens", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"}},
             "HIGH", {}, "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days.", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x22abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Text message agent", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"}},
             "HIGH", {}, "forta-text-messages-possible-hack", "description", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"

    def test_detect_alert_no_finding_large_tx_count(self):
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Account got approval for all tokens", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"}},
             "HIGH", {}, "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "0xdec08cb92a506B88411da9Ba290f3694BE223c26 obtained transfer approval for 3 assets by 6 accounts over period of 2 days.", ["0xdec08cb92a506B88411da9Ba290f3694BE223c26"], [], "0x22abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Text message agent", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"}},
             "HIGH", {}, "forta-text-messages-possible-hack", "description", ["0xdec08cb92a506B88411da9Ba290f3694BE223c26"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 0, "this should have not triggered a finding as the EOA has too many txs"

    def test_detect_alert_pos_no_repeat_finding(self):
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")
        
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Account got approval for all tokens", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"}},
             "HIGH", {}, "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days.", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x22abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Text message agent", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"}},
             "HIGH", {}, "forta-text-messages-possible-hack", "description", ["0x21e13f16838e2fe78056f5fd50251ffd6e7098b4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"]
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
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Suspicious Contract Creation by Tornado Cash funded account", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99"}},
             "HIGH", {}, "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Tornado Cash Funding", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"}},
             "HIGH", {}, "FUNDING-TORNADO-CASH", "description", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"],

            ["2022-04-30T23:55:17.284158264Z", "Money Laundering", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2"}},
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


    def test_detect_alert_pos_finding_combiner_with_cluster(self):
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        #   createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'
        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Entity identified", "ethereum",
             "INFO", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9"}},
             "INFO", {"entityAddresses":"0x7A2a13C269b3B908Ca5599956A248c5789Cc953f,0x91C1B58F24F5901276b1F2CfD197a5B73e31F96E"}, "ENTITY-CLUSTER", "Entity of size 2 has been identified. Transaction from 0x7a2a13c269b3b908ca5599956a248c5789cc953f created this entity.", ["0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4"], [], "0x12abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Account got approval for all tokens", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"}},
             "HIGH", {}, "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "0x7A2a13C269b3B908Ca5599956A248c5789Cc953f obtained transfer approval for 3 assets by 6 accounts over period of 2 days.", ["0x7A2a13C269b3B908Ca5599956A248c5789Cc953f"], [], "0x22abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"],

            ["2022-04-30T23:55:17.284158264Z", "Text message agent", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a026aa", "block": {"number": 14688607, "chainId": 1}, "bot": {"id": "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"}},
             "HIGH", {}, "forta-text-messages-possible-hack", "description", ["0x91C1B58F24F5901276b1F2CfD197a5B73e31F96E"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e11"]
        ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"
