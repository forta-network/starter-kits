from web3 import Web3
from hexbytes import HexBytes
from src.web3_constants_mock import *
from unittest.mock import MagicMock


class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        pass

    chain_id = 1

    def contract(self, address, abi):
        return ContractMock(address=address, abi=abi)

    def get_code(self, address):
        if address == Web3.toChecksumAddress(CONTRACT):
            return HexBytes(
                '0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea26469706673582212209a159a4f3847890f10bfb87871a61eba91c5dbf5ee3cf6398207e292eee22a1664736f6c63430008070033'
            )
        elif address == Web3.toChecksumAddress(NEW_EOA) or address == Web3.toChecksumAddress(OLD_EOA):
            return HexBytes('0x')
     
        return HexBytes('0x')

    def get_transaction_receipt(self, transaction_hash):
        transaction_receipt = MOCK_TX_HASH_LOGS_MAPPING[transaction_hash]
        return transaction_receipt

    def get_transaction_count(self, address):
        if address == "attacker":
            return 1
        else:
            return 5


class ContractMock:
    def __init__(self, address, abi, functions=None):
        self.address = address
        self.functions = functions if functions is not None else FunctionsMock()

        if self.address == "0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F":
            self.functions.symbol.return_value.call.return_value = "USDC"
        elif self.address == "0xCf117403474eEaC230DaCcB3b54c0dABeB94Ae22":
            self.functions.symbol.return_value.call.return_value = "USDT"
        else:
            self.functions.symbol.return_value.call.return_value = "NULL"

    def __call__(self, address, *args, **kwargs):
        return self

    def __getattr__(self, name):
        return getattr(self.functions, name)

class FunctionsMock:
    def __init__(self):
        self.symbol = MagicMock()