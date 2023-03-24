
from web3_mock import EOA_ADDRESS, CONTRACT

class BlockChainIndexerMock:
    @staticmethod
    def get_contracts(address: str, chain_id: int) -> set:
        contracts = set()
        if address == EOA_ADDRESS:
            contracts.add(CONTRACT)
        return contracts