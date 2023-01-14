from web3_mock import EOA_ADDRESS_NEW, EOA_ADDRESS_OLD
from datetime import datetime, timedelta

class BlockExplorerMock:

    def __init__(self, chain_id):
        pass

    def get_first_tx(self, address: str) -> datetime:
        if address.lower() == EOA_ADDRESS_NEW.lower():
            return datetime.now()
        elif address.lower() == EOA_ADDRESS_OLD.lower():
            return datetime.now() - timedelta(days=91)
        else:
            raise ValueError('Unknown address')
