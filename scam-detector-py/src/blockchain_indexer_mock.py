
from web3_mock import EOA_ADDRESS_SMALL_TX, CONTRACT

class BlockChainIndexerMock:
    @staticmethod
    def get_contracts(address: str, chain_id: int) -> set:
        contracts = set()
        if address == EOA_ADDRESS_SMALL_TX:
            contracts.add(CONTRACT)
        return contracts