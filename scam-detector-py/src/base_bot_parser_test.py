from forta_agent import create_alert_event,FindingSeverity, AlertEvent, Label, EntityType
from web3_mock import Web3Mock

from base_bot_parser import BaseBotParser

w3 = Web3Mock()

class TestBaseBotParser:

    def generate_alert(bot_id: str, alert_id: str, description: str, metadata={}, labels=[], alert_hash = '0xabc') -> AlertEvent:
        labels_tmp = [] if len(labels) == 0 else labels
        alert = {"alert":
                  {"name": "x",
                   "hash": alert_hash,
                   "addresses": [],
                   "description": description,
                   "alertId": alert_id,
                   "createdAt": "2022-11-18T03:01:21.457234676Z",
                   "source": {"bot": {'id': bot_id}, "block": {"chainId": 1, 'number': 5},  'transactionHash': '0x123'},
                   "metadata": metadata,
                   "labels": labels_tmp
                  }
                }
        
        return create_alert_event(alert)
    
    def test_get_cex_funded_address_metadata(self):
        description = "CEX Funding from FixFloat of 630000000000000 wei to 0xb3793e89bcde894a18c3f642f1c83ea0c0d08072"
        metadata = {"CEX_name":"FixFloat","anomaly_score":"0.00010274608069707849","to":"0xb3793e89bcde894a18c3f642f1c83ea0c0d08072","value":"630000000000000"}
        alert_event = TestBaseBotParser.generate_alert("0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb", "CEX-FUNDING-1", description=description, metadata=metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xb3793e89bcde894a18c3f642f1c83ea0c0d08072" in addresses, "this should be the attacker address"


    def test_get_addresses_address_poisoning_metadata(self):
        metadata = {"attackerAddresses":"0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168,0x55d398326f99059ff775485246999027b3197955,0x55d398326f99059ff775485246999027b3197956","anomaly_score":"0.0023634453781512603","logs_length":"24","phishingContract":"0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce","phishingEoa":"0xf6eb5da5850a1602d3d759395480179624cffe2c"}
        alert_event = TestBaseBotParser.generate_alert("0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502", "ADDRESS-POISONING", "description", metadata)

        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        poisoning_addresses_count = 0
        poisoner_addresses_count = 0
        scammer_contract_addresses = set()
        for address, metadata in addresses.items():
            if metadata['address_information'] == "poisoner":
                poisoner_addresses_count += 1
                scammer_contract_addresses = scammer_contract_addresses.union(metadata['scammer-contracts'])
            else:
                poisoning_addresses_count += 1
            
        assert poisoner_addresses_count == 1, "should have extracted 1 address; the EOA"
        assert "0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce" in scammer_contract_addresses
        assert poisoning_addresses_count == 3, "should have extracted 3 addresses"


    def test_get_addresses_wash_trading_metadata(self):
        metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
        alert_event = TestBaseBotParser.generate_alert("0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732", "NFT-WASH-TRADE", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert len(addresses) == 2, "should have extracted 2 addresses"

    def test_get_fromAddr_nft_order_metadata(self):
        metadata = {"interactedMarket": "opensea","transactionHash": "0x4fff109d9a6c030fce4de9426229a113524903f0babd6de11ee6c046d07226ff","toAddr": "0xBF96d79074b269F75c20BD9fa6DAed0773209EE7","fromAddr": "0x08395C15C21DC3534B1C3b1D4FA5264E5Bd7020C","initiator": "0xaefc35de05da370f121998b0e2e95698841de9b1","totalPrice": "0.001","avgItemPrice": "0.0002","contractAddress": "0xae99a698156ee8f8d07cbe7f271c31eeaac07087","floorPrice": "0.58","timestamp": "1671432035","floorPriceDiff": "-99.97%"}
        alert_event = TestBaseBotParser.generate_alert("0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac", "nft-phishing-sale", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xBF96d79074b269F75c20BD9fa6DAed0773209EE7".lower() in addresses.keys(), "this should be the attacker address"
        assert "0xaefc35de05da370f121998b0e2e95698841de9b1" in addresses.keys(), "this should also be attacker address"

    def test_get_sleep_minting_addresses(self):
        description = "An NFT Transfer was initiated by 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to transfer an NFT owned by 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. It had been previously minted by the 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. The NFT contract address is 0xd57474e76c9ebecc01b65a1494f0a1211df7bcd8"
        alert_event = TestBaseBotParser.generate_alert("0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba", "SLEEPMINT-3", description)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0x09b34e69363d37379e1c5e27fc793fdb5aca893d" in addresses, "this should be the attacker address"

    def test_get_hard_rug_pull_deployer(self):
        metadata = {"attacker_deployer_address":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6","rugpull_techniques":"HIDDENFEEMODIFIERS, HIDDENTRANSFERREVERTS","token_contract_address":"0x58089C1E2d5A4c5332F777A8698E8AA9A140159B"}
        alert_event = TestBaseBotParser.generate_alert("0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15", "HARD-RUG-PULL-1", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"
        assert "0x58089C1E2d5A4c5332F777A8698E8AA9A140159B".lower() in addresses["0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"]["scammer-contracts"]

    def test_get_soft_rug_pull_deployer(self):
        metadata = {"alert_hash":"0xe0c24c071cd7086bd09d1fd6d3066d0c0f7afb248e3d24fa65ec4f45ab6b5112 && 0x9335428e2fd787d228e423468c1780201ba5e9031e88f0b532d5fc0f97fdfe8f","alert_id":"SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION","bot_id":"0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1","contractAddress":"\"0xC63A4DD7c0a3F58cC619cf52163C88789C06F1B2\"","deployer":"\"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6\"","token":"\"0x5adebafbf2fd0d6808a7a1e823759de2df1df39e\"","txHashes":"\"0xaa671063f7468602adf7df8657978922d76c6f4e10371569c9eba9a16b503957\""}
        alert_event = TestBaseBotParser.generate_alert("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-1", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"
        assert "0xC63A4DD7c0a3F58cC619cf52163C88789C06F1B2".lower() in addresses["0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"]["scammer-contracts"]
        
    def test_get_rake_token_deployer(self):
        metadata = {"actualValueReceived":"6.941122496628802171176e+21","anomalyScore":"0.1845748187211602","attackerRakeTokenDeployer":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6","feeRecipient":"0xffaa85705ae216363e4e843b67ff3c238fcf0de2","from":"0x8245148b89d7e8c808ecf6e3f59ff26deb6caca8","pairAddress":"0x8cbf7cc41c2b556dab15e7addeab08490754be6b","rakeTokenAddress":"0xffaa85705ae216363e4e843b67ff3c238fcf0de2","rakeTokenDeployTxHash":"0x2d909882dba378c055f60d2c93c10b4a3bcf18100f83ec4b592cbf2d0823547d","rakedFee":"771235832958755796796","rakedFeePercentage":"10.00","totalAmountTransferred":"7.712358329587557967972e+21"}
        alert_event = TestBaseBotParser.generate_alert("0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11", "RAKE-TOKEN-CONTRACT-1", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"
        assert "0xffaa85705ae216363e4e843b67ff3c238fcf0de2" in addresses
        assert "0x8cbf7cc41c2b556dab15e7addeab08490754be6b" in addresses["0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"]["scammer-contracts"]
        assert "0x8cbf7cc41c2b556dab15e7addeab08490754be6b" in addresses["0xffaa85705ae216363e4e843b67ff3c238fcf0de2"]["scammer-contracts"]

    def test_get_native_ice_phishing(self):
        metadata = {"attacker":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        alert_event = TestBaseBotParser.generate_alert("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-1", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"

    def test_get_native_ice_phishing_contract(self):
        metadata = {"address":"0x70f8A2dcd67eD176d53dbfa22E163E235977BA61","anomalyScore":"0.0012903225806451613","attacker":"0xf363c1a1033d2381c58bcee4dc8f5a24ed3409cb"}
        alert_event = TestBaseBotParser.generate_alert("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-5", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xf363c1a1033d2381c58bcee4dc8f5a24ed3409cb" in addresses, "this should be the attacker address"
        assert "0x70f8A2dcd67eD176d53dbfa22E163E235977BA61".lower() in addresses["0xf363c1a1033d2381c58bcee4dc8f5a24ed3409cb"]["scammer-contracts"]

    def test_get_known_scammer(self):
        descrption = "Scam address 0xFB4d3EB37bDe8FA4B52c60AAbE55B3Cd9908EC73 got approval for 0x402E727AB6B0a8dcE41E74C4Bf385cEd14B6E80c's assets"
        alert_event = TestBaseBotParser.generate_alert("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SCAM-APPROVAL", descrption)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xFB4d3EB37bDe8FA4B52c60AAbE55B3Cd9908EC73".lower() in addresses, "this should be the attacker address"

    def test_get_token_impersonation(self):
        metadata = {"anomalyScore":"0.09375","newTokenContract":"0xb4d91be6d0894de00a3e57c24f7abb0233814c82","newTokenDeployer":"0x3b31724aff894849b90c48024bab38f25a5ee302","newTokenName":"Cross Chain Token","newTokenSymbol":"CCT","oldTokenContract":"0x115110423f4ad68a3092b298df7dc2549781108e","oldTokenDeployer":"0x80ec4276d31b1573d53f5db75841762607bc2166","oldTokenName":"Cross Chain Token","oldTokenSymbol":"CCT"}
        alert_event = TestBaseBotParser.generate_alert("0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127", "IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0x3b31724aff894849b90c48024bab38f25a5ee302" in addresses, "this should be the attacker address"
        assert "0xb4d91be6d0894de00a3e57c24f7abb0233814c82".lower() in addresses["0x3b31724aff894849b90c48024bab38f25a5ee302"]["scammer-contracts"]

    def test_get_blocksec_scammer_label(self):
        metadata = {}
        label = {"entity": "0x2ed12fb3146cd2eac390ea73acc83f80d6020b03","entityType": "ADDRESS","label": "phish","metadata": {},"confidence": 1}
        labels = [label]
        alert_event = TestBaseBotParser.generate_alert("0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534", "Ice Phishing", "description", metadata, labels)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0x2ed12fb3146cd2eac390ea73acc83f80d6020b03" in addresses, "this should be the scammer address"