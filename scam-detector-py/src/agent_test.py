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

    def test_get_addresses_address_poisoning_metadata(self):
        metadata = {"attackerAddresses":"0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168,0x55d398326f99059ff775485246999027b3197955","anomaly_score":"0.0023634453781512603","logs_length":"24","phishingContract":"0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce","phishingEoa":"0xf6eb5da5850a1602d3d759395480179624cffe2c"}
        addresses = agent.get_address_poisoning_addresses(metadata)
        assert len(addresses) == 4, "should have extracted 4 addresses"

    def test_get_addresses_wash_trading_metadata(self):
        metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
        addresses = agent.get_wash_trading_addresses(metadata)
        assert len(addresses) == 2, "should have extracted 2 addresses"

    def test_get_fromAddr_seaport_order_metadata(self):
        metadata = {"collectionFloor":"0.047","contractAddress":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6","contractName":"MG Land","currency":"ETH","fromAddr":"0xc81476ae9f2748725a36b326a1831200ed4f3ece","hash":"0x768eefcc8fdba3946749048bd8582fff41501cfe874fba2c9f0383ae2dfdd1cb","itemPrice":"0","market":"Opensea 🌊","quantity":"1","toAddr":"0xc81476ae9f2748725a36b326a1831200ed4f3ecf","tokenIds":"4297","totalPrice":"0"}
        toAddr = agent.get_seaport_order_attacker_address(metadata)
        assert toAddr == "0xc81476ae9f2748725a36b326a1831200ed4f3ecf", "this should be the attacker address"

    def test_fp_mitigation_proper_chain_id(self):
        # delete cache file
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")
        if os.path.exists("alerted_fp_addresses_key"):
            os.remove("alerted_fp_addresses_key")

        agent.initialize()

        agent.emit_new_fp_finding(w3)

        
        df_fps = pd.read_csv("fp_list.csv")
        assert len(agent.FINDINGS_CACHE) == len(df_fps[df_fps['chain_id']==1]), "this should have triggered FP findings"
        finding = agent.FINDINGS_CACHE[0]
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING-FALSE-POSITIVE", "should be FP mitigation finding"
        assert finding.labels is not None, "labels should not be empty"


    def test_detect_wash_trading(self):
        # delete cache file
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")

        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Possible Address Poisoning", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0xcb56309c68912594a316be9420b429fd0f385cbc226dd81261dbe934e7912e56", "block": {"number": 26435976, "chainId": 1}, "bot": {"id": "0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732"}},
             "MEDIUM", {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}, 
             "NFT-WASH-TRADE", "test Wash Trade on test.", ["0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB".lower(),"0xa53496B67eec749ac41B4666d63228A0fb0409cf".lower()], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"]
           ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        assert len(agent.FINDINGS_CACHE) == 2, "this should have triggered a finding for all two EOAs"
        finding = agent.FINDINGS_CACHE[0]
        assert finding.alert_id == "SCAM-DETECTOR-WASH-TRADE", "should be address poisoning finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"


    def test_detect_address_poisoning(self):
        # delete cache file
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")

        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Possible Address Poisoning", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0xc549d8cdee8a2799335785b0cc6f2cb29e7877e92a46edf5f0500ae1ebffbd79", "block": {"number": 26435976, "chainId": 1}, "bot": {"id": "0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502"}},
             "MEDIUM", {"attackerAddresses":"0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168,0x55d398326f99059ff775485246999027b3197955","anomaly_score":"0.0023634453781512603","logs_length":"24","phishingContract":"0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce","phishingEoa":"0xf6eb5da5850a1602d3d759395480179624cffe2c"}, 
             "ADDRESS-POISONING", "Possible address poisoning transaction.", ["0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168","0x55d398326f99059ff775485246999027b3197955","0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce","0xf6eb5da5850a1602d3d759395480179624cffe2c"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"]
           ], columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        assert len(agent.FINDINGS_CACHE) == 3, "this should have triggered a finding for all three EOAs"
        finding = agent.FINDINGS_CACHE[0]
        assert finding.alert_id == "SCAM-DETECTOR-ADDRESS-POISONING", "should be address poisoning finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_native_ice_phishing(self):
        # delete cache file
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")

        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "Possible native ice phishing with social engineering component attack", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0xc549d8cdee8a2799335785b0cc6f2cb29e7877e92a46edf5f0500ae1ebffbd79", "block": {"number": 26435976, "chainId": 1}, "bot": {"id": "0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0"}},
             "MEDIUM", {"anomalyScore":"0.000002526532805344122","attacker":"0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183","funcSig":"ClaimTokens()","victim":"0x7cfb946f174807a4746658274763e4d7642233df"}, 
             "NIP-1", "0x7cfb946f174807a4746658274763e4d7642233df sent funds to 0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183 with ClaimTokens() as input data", ["0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"]
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
        assert finding.alert_id == "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING", "should be address poisoning finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_fraudulent_seaport_orders(self):
        # delete cache file
        if os.path.exists("alerted_clusters_key"):
            os.remove("alerted_clusters_key")

        agent.initialize()

        forta_explorer = FortaExplorerMock()

        df_forta = pd.DataFrame([
            ["2022-04-30T23:55:17.284158264Z", "nft-phishing-alert", "ethereum",
             "SUSPICIOUS", {"transactionHash": "0xc549d8cdee8a2799335785b0cc6f2cb29e7877e92a46edf5f0500ae1ebffbd79", "block": {"number": 26435976, "chainId": 1}, "bot": {"id": "0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502"}},
             "MEDIUM", {"collectionFloor":"2.5","contractAddress":"0x764aeebcf425d56800ef2c84f2578689415a2daa","contractName":"SewerPass","currency":"ETH","fromAddr":"0x86031ba0a2fe6be8d55abfc7d51ddc4f91ba9f78","hash":"0xec6442b20f003ea9a38b8b51f7feef75f8e68618cd6d511d7ae44012786768ea","itemPrice":"0.0033333333333333335","market":"Opensea 🌊","quantity":"3","toAddr":"0x86031ba0a2fe6be8d55abfc7d51ddc4f91ba9f79","tokenIds":"19445,25417,5996","totalPrice":"0.01"}, 
             "SEAPORT-PHISHING-TRANSFER", "3 SewerPass id/s: 19445,25417,5996 sold on Opensea 🌊 for 0.01 ETH with a floor price of 2.5 ETH", ["0x86031ba0a2fe6be8d55abfc7d51ddc4f91ba9f78","0x86031ba0a2fe6be8d55abfc7d51ddc4f91ba9f79"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"]
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
        assert finding.alert_id == "SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER", "should be seaport order finding"
        assert finding.metadata is not None, "metadata should not be empty"
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
        label = finding.labels[0]
        assert label.entity == "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4", "entity should be attacker address"
        assert label.label == "scam", "entity should labeled as scam"
        assert label.confidence == 0.8, "entity should labeled with 0.8 confidence"
        assert label.metadata['alert_id'] == "SCAM-DETECTOR-ICE-PHISHING", "entity should labeled as ice phishing"
        assert label.metadata['chain_id'] == 1, "entity should labeled for chain_id 1"


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
