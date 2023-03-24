from blockchain_indexer_service import BlockChainIndexer
from web3_mock import EOA_ADDRESS

class TestBlockChainIndexer:
    def test_get_contract_deployments_has(self):
        contract_deployer_address = '0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4'  # euler finance exploiter
        deployed_contract = '0x036cec1a199234fc02f72d29e596a09440825f1c'  # euler finance exploiter contract
        contract_addresses = BlockChainIndexer.get_contracts(contract_deployer_address, 1)
        assert len(contract_addresses) > 0, "should be greater than 0"
        assert deployed_contract in contract_addresses, "should be in list"

    def test_get_contract_deployments_doesnt_have(self):
        address_without_deployments = '0xc66dfa84bc1b93df194bd964a41282da65d73c9a'  # euler finance exploiter 4
        contract_addresses = BlockChainIndexer.get_contracts(address_without_deployments, 1)
        assert len(contract_addresses) == 0, "should be 0"

    def test_calc_contract_address(self):
        contract_address = BlockChainIndexer.calc_contract_address(EOA_ADDRESS, 9)
        assert contract_address == "0xCBd4f0e0E01061Fc2CdedA99fA2e7FaaE21D85d0", "should be the same contract address"