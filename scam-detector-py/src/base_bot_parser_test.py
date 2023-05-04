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
        for address, metadata in addresses.items():
            if metadata['address_information'] == "poisoner":
                poisoner_addresses_count += 1
            else:
                poisoning_addresses_count += 1
            
        assert poisoner_addresses_count == 2, "should have extracted 2 addresses"
        assert poisoning_addresses_count == 3, "should have extracted 3 addresses"


    def test_get_addresses_wash_trading_metadata(self):
        metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
        alert_event = TestBaseBotParser.generate_alert("0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732", "NFT-WASH-TRADE", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert len(addresses) == 2, "should have extracted 2 addresses"

    def test_get_fromAddr_seaport_order_metadata(self):
        metadata = {"collectionFloor":"0.047","contractAddress":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6","contractName":"MG Land","currency":"ETH","fromAddr":"0xc81476ae9f2748725a36b326a1831200ed4f3ece","hash":"0x768eefcc8fdba3946749048bd8582fff41501cfe874fba2c9f0383ae2dfdd1cb","itemPrice":"0","market":"Opensea 🌊","quantity":"1","toAddr":"0xc81476ae9f2748725a36b326a1831200ed4f3ecf","tokenIds":"4297","totalPrice":"0"}
        alert_event = TestBaseBotParser.generate_alert("0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c", "SEAPORT-PHISHING-TRANSFER", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xc81476ae9f2748725a36b326a1831200ed4f3ecf" in addresses.keys(), "this should be the attacker address"

    def test_get_sleep_minting_addresses(self):
        description = "An NFT Transfer was initiated by 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to transfer an NFT owned by 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. It had been previously minted by the 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. The NFT contract address is 0xd57474e76c9ebecc01b65a1494f0a1211df7bcd8"
        alert_event = TestBaseBotParser.generate_alert("0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba", "SLEEPMINT-3", description)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0x09b34e69363d37379e1c5e27fc793fdb5aca893d" in addresses, "this should be the attacker address"

    def test_get_hard_rug_pull_deployer(self):
        metadata = {"attacker_deployer_address":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        alert_event = TestBaseBotParser.generate_alert("0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15", "HARD-RUG-PULL-1", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"

    def test_get_soft_rug_pull_deployer(self):
        metadata = {"deployer":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        alert_event = TestBaseBotParser.generate_alert("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-1", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"
        
    def test_get_rake_token_deployer(self):
        metadata = {"attackerRakeTokenDeployer":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        alert_event = TestBaseBotParser.generate_alert("0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11", "RAKE-TOKEN-CONTRACT-1", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"

    def test_get_native_ice_phishing(self):
        metadata = {"attacker":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        alert_event = TestBaseBotParser.generate_alert("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-1", "description", metadata)
        addresses = BaseBotParser.get_scammer_addresses(w3,alert_event)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"

