from datetime import datetime

from utils import Utils
from web3_mock import CONTRACT, EOA_ADDRESS_SMALL_TX, Web3Mock, EOA_ADDRESS_LARGE_TX

w3 = Web3Mock()

class TestUtils:
    def test_is_contract_eoa(self):
        assert not Utils.is_contract(w3, EOA_ADDRESS_SMALL_TX), "EOA shouldn't be identified as a contract"

    def test_is_contract_contract(self):
        assert Utils.is_contract(w3, CONTRACT), "Contract should be identified as a contract"

    def test_is_contract_contract_eoa(self):
        assert not Utils.is_contract(w3, f"{CONTRACT},{EOA_ADDRESS_SMALL_TX}"), "EOA & Contract shouldnt be identified as a contract"

    def test_is_contract_contracts(self):
        assert Utils.is_contract(w3, f"{CONTRACT},{CONTRACT}"), "Contracts should be identified as a contract"

    def test_is_contract_null(self):
        assert not Utils.is_contract(w3, '0x0000000000a00000000000000000000000000000'), "EOA shouldn't be identified as a contract"

    def test_is_address_valid(self):
        assert Utils.is_address(w3, '0x7328BBc3EaCfBe152f569f2C09f96f915F2C8D73'), "this should be a valid address"

    def test_is_address_aaa(self):
        assert not Utils.is_address(w3, '0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_is_addresses_aaa(self):
        assert not Utils.is_address(w3, f'0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73,{EOA_ADDRESS_SMALL_TX}'), "this shouldnt be a valid address"

    def test_is_address_aAa(self):
        assert not Utils.is_address(w3, '0x7328BBaaaaAaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_etherscan_label(self):
        label = Utils.get_etherscan_label("0xffc0022959f58aa166ce58e6a38f711c95062b99")
        assert 'uniswap' in label, "this should be a uniswap address"

    def test_max_tx_count(self):
        assert Utils.get_max_tx_count(w3, EOA_ADDRESS_SMALL_TX) == 1999, "this should be 1999"

    def test_is_in_fp_mitigation_list(self):
        Utils.update_fp_list(1)
        assert Utils.is_in_fp_mitigation_list("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"), "it should be in list for chain 1"

    def test_fp_etherscan_label(self):
        assert Utils.is_fp(w3, "0xffc0022959f58aa166ce58e6a38f711c95062b99"), "this should be a false positive"

    def test_fp_max_tx_count(self):
        assert Utils.is_fp(w3, EOA_ADDRESS_LARGE_TX), "this should be a false positive"

    def test_fp_mitigation_addresses(self):
        assert Utils.is_fp(w3, "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"), "this should be a false positive"

    def test_get_total_shards(self):
        assert Utils.get_total_shards(w3) == 8, "this should be 8"

    def test_get_shard(self):
        
        assert Utils.get_shard(1, datetime(2023, 1, 1).timestamp()) == 0, "this should be 0"

    def test_get_bot_version(self):
        assert "." in Utils.get_bot_version()
