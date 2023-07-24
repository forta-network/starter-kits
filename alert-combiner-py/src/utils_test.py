from forta_agent import get_json_rpc_url
from web3 import Web3
from utils import Utils
from web3_mock import CONTRACT, EOA_ADDRESS, Web3Mock

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

class TestUtils:
    def test_is_contract_eoa(self):
        assert not Utils.is_contract(w3, EOA_ADDRESS), "EOA shouldn't be identified as a contract"

    def test_is_contract_contract(self):
        assert Utils.is_contract(w3, CONTRACT), "Contract should be identified as a contract"

    def test_is_contract_contract_eoa(self):
        assert not Utils.is_contract(w3, f"{CONTRACT},{EOA_ADDRESS}"), "EOA & Contract shouldnt be identified as a contract"

    def test_is_contract_contracts(self):
        assert Utils.is_contract(w3, f"{CONTRACT},{CONTRACT}"), "Contracts should be identified as a contract"

    def test_is_contract_null(self):
        assert not Utils.is_contract(w3, '0x0000000000a00000000000000000000000000000'), "EOA shouldn't be identified as a contract"

    def test_is_address_valid(self):
        assert Utils.is_address('0x7328BBc3EaCfBe152f569f2C09f96f915F2C8D73'), "this should be a valid address"

    def test_is_address_aaa(self):
        assert not Utils.is_address('0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_is_addresses_aaa(self):
        assert not Utils.is_address(f'0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73,{EOA_ADDRESS}'), "this shouldnt be a valid address"

    def test_is_address_aAa(self):
        assert not Utils.is_address('0x7328BBaaaaAaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_etherscan_label(self):
        label = Utils.get_etherscan_label("0xffc0022959f58aa166ce58e6a38f711c95062b99")
        assert 'uniswap' in label, "this should be a uniswap address"
  
    def test_get_total_shards(self):
        assert Utils.get_total_shards(w3) == 8, "this should be 8"

    def test_is_beta(self):
        assert Utils.is_beta() is not None

