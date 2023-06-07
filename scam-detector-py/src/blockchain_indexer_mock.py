
from web3_mock import EOA_ADDRESS_SMALL_TX, CONTRACT, EOA_ADDRESS_LARGE_TX, CONTRACT2

class BlockChainIndexerMock:
    @staticmethod
    def get_contracts(address: str, chain_id: int) -> set:
        contracts = set()
        if address.lower() == EOA_ADDRESS_SMALL_TX.lower():
            contracts.add(CONTRACT)
        if address.lower() == EOA_ADDRESS_LARGE_TX.lower():
            contracts.add(CONTRACT2)
        return contracts