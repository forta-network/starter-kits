from base_bot_parser import BaseBotParser

class TestBaseBotParser:

    def test_get_addresses_address_poisoning_metadata(self):
        metadata = {"attackerAddresses":"0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168,0x55d398326f99059ff775485246999027b3197955,0x55d398326f99059ff775485246999027b3197956","anomaly_score":"0.0023634453781512603","logs_length":"24","phishingContract":"0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce","phishingEoa":"0xf6eb5da5850a1602d3d759395480179624cffe2c"}
        addresses = BaseBotParser.get_address_poisoning_addresses_poisoner(metadata)
        assert len(addresses) == 2, "should have extracted 2 addresses"

        addresses = BaseBotParser.get_address_poisoning_addresses_poisoning(metadata)
        assert len(addresses) == 3, "should have extracted 3 addresses"

    def test_get_addresses_wash_trading_metadata(self):
        metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
        addresses = BaseBotParser.get_wash_trading_addresses(metadata)
        assert len(addresses) == 2, "should have extracted 2 addresses"

    def test_get_fromAddr_seaport_order_metadata(self):
        metadata = {"collectionFloor":"0.047","contractAddress":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6","contractName":"MG Land","currency":"ETH","fromAddr":"0xc81476ae9f2748725a36b326a1831200ed4f3ece","hash":"0x768eefcc8fdba3946749048bd8582fff41501cfe874fba2c9f0383ae2dfdd1cb","itemPrice":"0","market":"Opensea 🌊","quantity":"1","toAddr":"0xc81476ae9f2748725a36b326a1831200ed4f3ecf","tokenIds":"4297","totalPrice":"0"}
        toAddr = BaseBotParser.get_seaport_order_attacker_address(metadata)
        assert toAddr == "0xc81476ae9f2748725a36b326a1831200ed4f3ecf", "this should be the attacker address"

    def test_get_sleep_minting_addresses(self):
        description = "An NFT Transfer was initiated by 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to transfer an NFT owned by 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. It had been previously minted by the 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. The NFT contract address is 0xd57474e76c9ebecc01b65a1494f0a1211df7bcd8"
        addresses = BaseBotParser.get_sleep_minting_addresses(description)
        assert "0x09b34e69363d37379e1c5e27fc793fdb5aca893d" in addresses, "this should be the attacker address"

    def test_get_hard_rug_pull_deployer(self):
        metadata = {"attacker_deployer_address":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        addresses = BaseBotParser.get_hard_rug_pull_deployer(metadata)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"

    def test_get_soft_rug_pull_deployer(self):
        metadata = {"deployer":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        addresses = BaseBotParser.get_soft_rug_pull_deployer(metadata)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"
        
    def test_get_rake_token_deployer(self):
        metadata = {"attackerRakeTokenDeployer":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        addresses = BaseBotParser.get_rake_token_deployer(metadata)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"

    def test_get_native_ice_phishing(self):
        metadata = {"attacker":"0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6"}
        addresses = BaseBotParser.get_native_ice_phishing_address(metadata)
        assert "0xe75512aa3bec8f00434bbd6ad8b0a3fbff100ad6" in addresses, "this should be the attacker address"

    def test_get_scammer_addresses(self):
        assert False, "not implemented"