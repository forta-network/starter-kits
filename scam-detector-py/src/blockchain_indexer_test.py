from blockchain_indexer_service import BlockChainIndexer

class TestBlockChainIndexer:
    def test_get_contract_deployments_has(self):
        contract_deployer_address = '0xf55037738604fddfc4043d12f25124e94d7d1780'  # chainlink deployer
        deployed_contract = '0x514910771af9ca656af840dff83e8264ecf986ca'  # chainlink token
        contract_addresses = BlockChainIndexer.get_contracts(contract_deployer_address)
        assert len(contract_addresses) > 0, "should be greater than 0"
        assert deployed_contract in contract_addresses, "should be in list"

    def test_get_contract_deployments_doesnt_have(self):
        address_without_deployments = '0xc66dfa84bc1b93df194bd964a41282da65d73c9a'  # euler finance exploiter 4
        contract_addresses = BlockChainIndexer.get_contracts(address_without_deployments)
        assert len(contract_addresses) == 0, "should be 0"
