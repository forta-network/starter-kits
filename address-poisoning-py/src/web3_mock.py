from web3 import Web3
from hexbytes import HexBytes
from web3_constants_mock import *
from unittest.mock import MagicMock
import asyncio


class Web3Mock:
    def __init__(self):
        self.eth = EthMock()

    @staticmethod
    def to_checksum_address(address):
        return Web3.to_checksum_address(address)


class EthMock:
    def __init__(self):
        self.chain_id = 1

    def contract(self, address, abi):
        return ContractMock(address=address, abi=abi)

    async def get_code(self, address):
        if address == Web3.to_checksum_address(CONTRACT):
            return HexBytes(
                '0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea26469706673582212209a159a4f3847890f10bfb87871a61eba91c5dbf5ee3cf6398207e292eee22a1664736f6c63430008070033'
            )
        elif address == Web3.to_checksum_address(NEW_EOA) or address == Web3.to_checksum_address(OLD_EOA):
            return HexBytes('0x')

        return HexBytes('0x')

    async def get_transaction_receipt(self, transaction_hash):
        transaction_receipt = MOCK_TX_HASH_LOGS_MAPPING[transaction_hash]
        return transaction_receipt

    async def get_transaction_count(self, address):
        if address == "attacker":
            return 1
        else:
            return 5


class ContractMock:
    def __init__(self, address, abi):
        self.address = address
        self.abi = abi
        self.functions = FunctionsMock(address)

    async def __call__(self, address, *args, **kwargs):
        return self

    def __getattr__(self, name):
        return getattr(self.functions, name)


class FunctionsMock:
    def __init__(self, address):
        self.address = address
        self.symbol_return_values = {}
        self._set_symbol_return_value("0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F", "USDC")
        self._set_symbol_return_value("0xCf117403474eEaC230DaCcB3b54c0dABeB94Ae22", "USDT")

    def _set_symbol_return_value(self, address, symbol):
        self.symbol_return_values[address.lower()] = symbol

    def symbol(self):
        async def call():
            return self.symbol_return_values.get(self.address.lower(), "NULL")
        return MagicMock(call=call)
