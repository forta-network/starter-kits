from constants import ETHERSCAN_API_KEY
from etherscan import Etherscan

EOA = '0x6162759eDAd730152F0dF8115c698a42E666157F'
VERIFIED_CONTRACT = '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984'
UNVERIFIED_CONTRACT = '0xe39f3c40966df56c69aa508d8ad459e77b8a2bc1'


class TestEtherscan:
    def test_unverified_contract(self):
        assert not Etherscan(ETHERSCAN_API_KEY).is_verified(UNVERIFIED_CONTRACT), "Etherscan incorrectly verified unverified contract"

    def test_verified_contract(self):
        assert Etherscan(ETHERSCAN_API_KEY).is_verified(VERIFIED_CONTRACT), "Etherscan didnt verify verified contract"

    def test_eoa(self):
        assert not Etherscan(ETHERSCAN_API_KEY).is_verified(EOA), "Etherscan verified an EOA"
