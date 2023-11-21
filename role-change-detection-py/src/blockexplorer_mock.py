from web3_mock import VERIFIED_CONTRACT, NEW_EOA

class BlockExplorerMock:
    def __init__(self, chain_id):
        pass
    

    def get_abi(self, address):
        return '[{MOCK_ABI: PLACEHOLDER}]'