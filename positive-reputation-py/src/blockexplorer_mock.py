from web3_mock import EOA_ADDRESS_NEW, EOA_ADDRESS_OLD, EOA_ADDRESS_CONTRACT_DEPLOYER
from datetime import datetime, timedelta

class BlockExplorerMock:

    def __init__(self, chain_id):
        pass

    def get_first_tx(self, address: str) -> datetime:
        if address.lower() == EOA_ADDRESS_NEW.lower():
            return datetime.now()
        elif address.lower() == EOA_ADDRESS_OLD.lower():
            return datetime.now() - timedelta(days=91)
        elif address.lower() == EOA_ADDRESS_CONTRACT_DEPLOYER.lower():
            return datetime.now() - timedelta(days=31)
        else:
            raise ValueError('Unknown address')

    def has_deployed_high_tx_count_contract(self, address: str, chain_id: int) -> bool:
        if address.lower() == EOA_ADDRESS_CONTRACT_DEPLOYER.lower():
            return True
        else:
            return False