from blockchain_indexer_service import BlockChainIndexer
from web3_mock import EOA_ADDRESS_SMALL_TX

class TestBlockChainIndexer:
    def test_get_contract_deployments_has_zettablock(self):
        contract_deployer_address = '0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4'  # euler finance exploiter
        deployed_contract = '0x036cec1a199234fc02f72d29e596a09440825f1c'  # euler finance exploiter contract
        contract_addresses = BlockChainIndexer.get_contracts(contract_deployer_address, 1, disable_etherscan=True, disable_zettablock=False)
        assert len(contract_addresses) > 0, "should be greater than 0"
        assert deployed_contract in contract_addresses, "should be in list"

    def test_get_contract_deployments_has_etherscan(self):
        contract_deployer_address = '0x0cf83143f0ab9d6e178fc7f141205ec2992266c8'  # some deployer on fantom
        deployed_contract = '0x82487df5b4cf19db597a092c8103759466be9e5a'  # some contract on fantom
        contract_addresses = BlockChainIndexer.get_contracts(contract_deployer_address, 250, disable_etherscan=False, disable_zettablock=True)
        assert len(contract_addresses) > 0, "should be greater than 0"
        assert deployed_contract in contract_addresses, "should be in list"

    def test_get_contract_deployments_doesnt_have(self):
        address_without_deployments = '0xc66dfa84bc1b93df194bd964a41282da65d73c9a'  # euler finance exploiter 4
        contract_addresses = BlockChainIndexer.get_contracts(address_without_deployments, 1)
        assert len(contract_addresses) == 0, "should be 0"

    def test_calc_contract_address(self):
        contract_address = BlockChainIndexer.calc_contract_address(EOA_ADDRESS_SMALL_TX, 9)
        assert contract_address == "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7", "should be the same contract address"

    def test_has_deployed_high_tx_count_contract(self):
        contract_deployer_address = '0x41545f8b9472d758bb669ed8eaeeecd7a9c4ec29,0xfc19e4ce0e0a27b09f2011ef0512669a0f76367a' # Random address (Fort Token), Binance: Deployer 3
        has_deployed_high_tx_count_contract = BlockChainIndexer.has_deployed_high_tx_count_contract(contract_deployer_address, 56)
        assert has_deployed_high_tx_count_contract == True, "should be true"

    def test_get_etherscan_labels(self):
        address = '0x1673888242bad06cc87a7bcaff392cb27218b3e3' # Uniswap V3: FORT-USDC 
        labels = BlockChainIndexer.get_etherscan_labels((address,))
        assert labels == {'0x1673888242bad06cc87a7bcaff392cb27218b3e3': {'labels': ['Uniswap'], 'nametag': 'Uniswap V3: FORT-USDC'}},"should return one Uniswap label and a nametag"

