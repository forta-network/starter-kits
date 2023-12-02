from blockexplorer import BlockExplorer
from datetime import datetime, timedelta


class TestBlockExplorer:
    def test_get_first_tx(self):
        first_tx = BlockExplorer(1).get_first_tx("0x690B9A9E9aa1C9dB991C7721a92d351Db4FaC990")
        assert first_tx < datetime.now() - timedelta(days=55), "first_tx is too low"

    def test_has_deployed_high_tx_count_contract(self):
        contract_deployer_address = '0xfc19e4ce0e0a27b09f2011ef0512669a0f76367a' # Binance: Deployer 3
        has_deployed_high_tx_count_contract = BlockExplorer(56).has_deployed_high_tx_count_contract(contract_deployer_address, 56)
        assert has_deployed_high_tx_count_contract == True, "should be true"