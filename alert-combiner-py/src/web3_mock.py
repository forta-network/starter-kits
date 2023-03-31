from hexbytes import HexBytes
from datetime import datetime

EOA_ADDRESS = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4'  # small tx count
EOA_ADDRESS_2 = '0x1c5dCdd006EA78a7E4783f9e6021C32935bbbbbb'  # small tx count
CONTRACT = '0x2320A28f52334d62622cc2EaFa15DE55F9987eD9'


class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock()

    def chain_id(self):
        return 1

    def get_block(self, block_number):
        return BlockMock()

    def get_code(self, address):
        if address == EOA_ADDRESS or address == EOA_ADDRESS_2:
            return HexBytes('0x')
        elif address == CONTRACT:
            return HexBytes('0x0000000000000000000000000000000000000000000000000000000000000005')
        else:
            return HexBytes('0x')


class BlockMock:
    timestamp = datetime.now().timestamp()


class ContractMock:
    def __init__(self):
        self.functions = FunctionsMock()

    def __call__(self, address, *args, **kwargs):
        return self


class FunctionsMock:
    def __init__(self):
        self.return_value = None

    def call(self, *_, **__):
        return self.return_value
